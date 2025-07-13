package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
	"github.com/pelletier/go-toml/v2"
	"golang.org/x/sync/errgroup"
)

const (
	v2flyRepoURL   = "https://github.com/v2fly/domain-list-community.git"
	v2flyCloneDir  = "tmp/domain-list-community"
	v2flyDataDir   = "tmp/domain-list-community/data"
	configPath     = "scripts/config/parsing-domains.toml"
	domainsFile    = "data/domains/domains-summary.lst"
	categoriesDir  = "data/domains/services"
	groupsDir      = "data/domains/groups"
	requestTimeout = 15 * time.Second
)

var (
	commentRegex      = regexp.MustCompile(`^\s*(#|;|//|--).*`)
	prefixRegex       = regexp.MustCompile(`^\s*-\s*|^(full:|domain:|keyword:)`)
	httpRegex         = regexp.MustCompile(`^https?://|^//`)
	wwwRegex          = regexp.MustCompile(`^www\d*\.`)
	specialCharsRegex = regexp.MustCompile(`[\\^$*+?()\[\]{}|]`)
)

var httpCache sync.Map

type Config struct {
	Services map[string]ServiceConfig `toml:"services"`
	Groups   map[string]GroupConfig   `toml:"groups"`
}

type ServiceConfig struct {
	URL     []string `toml:"url"`
	Domains []string `toml:"domains"`
	V2fly   []string `toml:"v2fly"`
	General *bool    `toml:"general,omitempty"` // Изменено на указатель с omitempty
}

type GroupConfig struct {
	Include []string `toml:"include"`
	URL     []string `toml:"url"`
	Domains []string `toml:"domains"`
	V2fly   []string `toml:"v2fly"`
	General *bool    `toml:"general,omitempty"` // Изменено на указатель с omitempty
}

func getGeneralValue(general *bool) bool {
	if general == nil {
		return true // Если ключ отсутствует, то general = true
	}
	return *general
}

func runDomainScripts() error {
	// Получаем абсолютный путь к директории скриптов
	scriptDir, err := filepath.Abs("scripts/config/domains-scripts")
	if err != nil {
		return fmt.Errorf("get absolute path: %w", err)
	}

	logger.Info("Running domain scripts in %s", scriptDir)

	// Проверяем существование директории
	if _, err := os.Stat(scriptDir); os.IsNotExist(err) {
		logger.Info("Scripts directory %s does not exist, skipping", scriptDir)
		return nil
	}

	var goFiles []string
	err = filepath.Walk(scriptDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return fmt.Errorf("access path %s: %w", path, err)
		}
		if !info.IsDir() && strings.HasSuffix(info.Name(), ".go") && !strings.HasSuffix(info.Name(), "_test.go") {
			logger.Info("Found script: %s", path)
			goFiles = append(goFiles, path)
		}
		return nil
	})

	if err != nil {
		return fmt.Errorf("walk scripts directory: %w", err)
	}

	if len(goFiles) == 0 {
		logger.Info("No Go scripts found in %s", scriptDir)
		return nil
	}

	// Переходим в директорию скриптов для выполнения
	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get current directory: %w", err)
	}
	defer os.Chdir(originalDir) // Возвращаемся обратно после выполнения

	if err := os.Chdir(scriptDir); err != nil {
		return fmt.Errorf("change to scripts directory: %w", err)
	}

	for _, file := range goFiles {
		// Используем только имя файла, так как мы уже в нужной директории
		scriptName := filepath.Base(file)
		logger.Info("Executing script: %s", scriptName)

		cmd := exec.Command("go", "run", scriptName)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr

		start := time.Now()
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("script %s failed after %v: %w", scriptName, time.Since(start), err)
		}
		logger.Info("Script %s completed successfully in %v", scriptName, time.Since(start))
	}
	return nil
}

type LeveledLogger struct{}

func (l *LeveledLogger) Info(format string, v ...interface{}) {
	log.Printf("[INFO] "+format, v...)
}

func (l *LeveledLogger) Warn(format string, v ...interface{}) {
	log.Printf("[WARN] "+format, v...)
}

func (l *LeveledLogger) Error(format string, v ...interface{}) {
	log.Printf("[ERROR] "+format, v...)
}

var logger = &LeveledLogger{}

type trieNode struct {
	children map[string]*trieNode
	end      bool
}

func cleanDomainLine(line string) ([]string, error) {
	line = commentRegex.ReplaceAllString(line, "")
	line = strings.SplitN(line, "#", 2)[0]
	line = strings.TrimSpace(line)
	if line == "" {
		return nil, nil
	}

	if strings.HasPrefix(line, "regexp:") {
		return handleRegexPattern(strings.TrimPrefix(line, "regexp:"))
	}

	line = prefixRegex.ReplaceAllString(line, "")
	if !strings.Contains(line, "://") {
		line = "http://" + line
	}

	parsed, err := url.Parse(line)
	if err != nil {
		return nil, nil
	}

	host := parsed.Hostname()
	if host == "" {
		return nil, nil
	}

	host = strings.ToLower(host)
	host = wwwRegex.ReplaceAllString(host, "")
	return []string{host}, nil
}

func handleRegexPattern(pattern string) ([]string, error) {
	// Удаляем флаги (например, "@cn" в конце)
	if idx := strings.Index(pattern, " @"); idx != -1 {
		pattern = pattern[:idx]
	}

	// Создаем движок с поддержкой сложных выражений
	re, err := regexp2.Compile(pattern, regexp2.None)
	if err != nil {
		logger.Warn("Error compiling regex: %s - %v", pattern, err)
		return nil, nil
	}

	// Извлекаем домены из регулярного выражения
	domains := extractDomainsFromRegex(re)
	if len(domains) > 0 {
		return domains, nil
	}

	logger.Warn("Regex not supported or no domains extracted: %s", pattern)
	return nil, nil
}

func extractDomainsFromRegex(re *regexp2.Regexp) []string {
	pattern := re.String()
	var domains []string

	// Упрощаем шаблон для извлечения доменов
	pattern = strings.ReplaceAll(pattern, `\`, "")
	pattern = strings.ReplaceAll(pattern, `(`, "")
	pattern = strings.ReplaceAll(pattern, `)`, "")
	pattern = strings.ReplaceAll(pattern, `^`, "")
	pattern = strings.ReplaceAll(pattern, `$`, "")
	pattern = strings.ReplaceAll(pattern, `.*`, "")
	pattern = strings.ReplaceAll(pattern, `.+`, "")
	pattern = strings.ReplaceAll(pattern, `\S+`, "")
	pattern = strings.ReplaceAll(pattern, `\d+`, "")
	pattern = strings.ReplaceAll(pattern, `|`, " ")

	// Извлекаем потенциальные домены
	domainRegex := regexp.MustCompile(`[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*`)
	matches := domainRegex.FindAllString(pattern, -1)

	for _, match := range matches {
		// Убираем лишние символы в начале/конце
		match = strings.Trim(match, ".-")

		// Проверяем, что это валидный домен
		if strings.Contains(match, ".") &&
			!strings.ContainsAny(match, "()[]{}|+*?$\\") &&
			!strings.HasPrefix(match, "-") &&
			!strings.HasSuffix(match, "-") {

			// Извлекаем основной домен (последние 2 части)
			parts := strings.Split(match, ".")
			if len(parts) >= 2 {
				domain := strings.Join(parts[len(parts)-2:], ".")
				domains = append(domains, strings.ToLower(domain))
			}
		}
	}

	return unique(domains)
}

func unique(slice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range slice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func newDomainTrie() *trieNode {
	return &trieNode{children: make(map[string]*trieNode)}
}

func (t *trieNode) insert(domain string) {
	parts := strings.Split(domain, ".")
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if t.children[part] == nil {
			t.children[part] = newDomainTrie()
		}
		t = t.children[part]
	}
	t.end = true
}

func (t *trieNode) containsSuperdomain(domain string) bool {
	parts := strings.Split(domain, ".")
	node := t
	for i := len(parts) - 1; i >= 0; i-- {
		part := parts[i]
		if node.end {
			return true
		}
		if node.children[part] == nil {
			return false
		}
		node = node.children[part]
	}
	return node.end
}

func filterDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}

	uniqueSet := make(map[string]struct{})
	for _, d := range domains {
		uniqueSet[d] = struct{}{}
	}
	uniqueDomains := make([]string, 0, len(uniqueSet))
	for d := range uniqueSet {
		uniqueDomains = append(uniqueDomains, d)
	}

	sort.Slice(uniqueDomains, func(i, j int) bool {
		return strings.Count(uniqueDomains[i], ".") < strings.Count(uniqueDomains[j], ".")
	})

	trie := newDomainTrie()
	result := make([]string, 0, len(uniqueDomains))
	for _, d := range uniqueDomains {
		if !trie.containsSuperdomain(d) {
			result = append(result, d)
			trie.insert(d)
		}
	}
	sort.Strings(result)
	return result
}

func downloadContent(ctx context.Context, url string) ([]byte, error) {
	const maxRetries = 3
	const initialDelay = 1 * time.Second
	var lastError error

	for attempt := 0; attempt < maxRetries; attempt++ {
		if attempt > 0 {
			delay := initialDelay * time.Duration(attempt*attempt)
			logger.Info("Retry #%d for %s after %v", attempt+1, url, delay)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(delay):
			}
		}

		reqCtx, cancel := context.WithTimeout(ctx, requestTimeout)
		defer cancel()

		req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
		if err != nil {
			lastError = fmt.Errorf("create request: %w", err)
			continue
		}

		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			lastError = fmt.Errorf("execute request: %w", err)
			continue
		}

		if resp.StatusCode == http.StatusOK {
			data, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil {
				lastError = fmt.Errorf("read response: %w", err)
				continue
			}
			return data, nil
		}

		resp.Body.Close()
		lastError = fmt.Errorf("unexpected status: %d", resp.StatusCode)
	}

	return nil, fmt.Errorf("after %d attempts: %w", maxRetries, lastError)
}

func processDomainSource(ctx context.Context, source string) ([]string, error) {
	if strings.HasPrefix(source, "http") {
		logger.Info("Downloading domain source: %s", source)
		data, err := downloadContent(ctx, source)
		if err != nil {
			return nil, fmt.Errorf("download failed: %w", err)
		}

		var domains []string
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			result, err := cleanDomainLine(scanner.Text())
			if err != nil {
				logger.Warn("Error cleaning line: %v", err)
				continue
			}
			if result != nil {
				domains = append(domains, result...)
			}
		}
		return domains, scanner.Err()
	}

	return cleanDomainLine(source)
}

func processDomainSources(ctx context.Context, urls, domains []string, v2flyData map[string][]string, v2flyKeys []string) ([]string, error) {
	var result []string

	for _, u := range urls {
		ds, err := processDomainSource(ctx, u)
		if err != nil {
			logger.Warn("Error processing URL %s: %v", u, err)
			continue
		}
		result = append(result, ds...)
	}

	for _, d := range domains {
		cleaned, err := cleanDomainLine(d)
		if err != nil {
			logger.Warn("Error cleaning domain %s: %v", d, err)
			continue
		}
		if cleaned != nil {
			result = append(result, cleaned...)
		}
	}

	for _, key := range v2flyKeys {
		if data, ok := v2flyData[key]; ok {
			result = append(result, data...)
		}
	}

	return result, nil
}

func parseV2flyFile(filename string, visited map[string]bool) ([]string, error) {
	if visited[filename] {
		return nil, nil
	}
	visited[filename] = true

	path := filepath.Join(v2flyDataDir, filename)
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var domains []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if strings.HasPrefix(line, "include:") {
			includedFile := strings.TrimSpace(strings.TrimPrefix(line, "include:"))
			includedDomains, err := parseV2flyFile(includedFile, visited)
			if err != nil {
				return nil, err
			}
			domains = append(domains, includedDomains...)
		} else {
			result, err := cleanDomainLine(line)
			if err != nil {
				logger.Warn("Error parsing v2fly line: %v", err)
				continue
			}
			if result != nil {
				domains = append(domains, result...)
			}
		}
	}
	return domains, scanner.Err()
}

func processV2flyCategories(ctx context.Context, categories []string) (map[string][]string, error) {
	if len(categories) == 0 {
		return nil, nil
	}

	logger.Info("Processing v2fly categories: %v", categories)

	if err := os.RemoveAll(v2flyCloneDir); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("remove dir: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(v2flyCloneDir), 0755); err != nil {
		return nil, fmt.Errorf("create dir: %w", err)
	}

	logger.Info("Cloning v2fly repository...")
	cmd := exec.CommandContext(ctx, "git", "clone", "--depth", "1", v2flyRepoURL, v2flyCloneDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("git clone failed: %w\nOutput: %s", err, output)
	}

	result := make(map[string][]string)
	for _, category := range categories {
		domains, err := parseV2flyFile(category, make(map[string]bool))
		if err != nil {
			logger.Warn("Error parsing v2fly category %s: %v", category, err)
			continue
		}
		if len(domains) > 0 {
			result[category] = domains
		}
	}
	return result, nil
}

func saveDomains(path string, domains []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create dir: %w", err)
	}

	existing := make(map[string]struct{})
	if data, err := os.ReadFile(path); err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				existing[line] = struct{}{}
			}
		}
	}

	allDomains := make(map[string]struct{})
	for _, d := range domains {
		allDomains[d] = struct{}{}
	}
	for d := range existing {
		allDomains[d] = struct{}{}
	}

	uniqueDomains := make([]string, 0, len(allDomains))
	for d := range allDomains {
		uniqueDomains = append(uniqueDomains, d)
	}

	filtered := filterDomains(uniqueDomains)
	data := strings.Join(filtered, "\n") + "\n"
	return os.WriteFile(path, []byte(data), 0644)
}

func processServices(ctx context.Context, config Config) (map[string][]string, map[string]bool, []string, map[string][]string, map[string][]string, error) {
	v2flyData := make(map[string][]string)
	serviceDomains := make(map[string][]string)
	serviceGeneral := make(map[string]bool)
	serviceDomainsForCleanup := make(map[string][]string) // Новая карта для отслеживания доменов сервисов для очистки
	allExcluded := make(map[string]struct{})
	var mu sync.Mutex

	// Собираем v2fly категории из сервисов И групп
	var v2flyCategories []string
	for _, cfg := range config.Services {
		v2flyCategories = append(v2flyCategories, cfg.V2fly...)
	}
	// Добавляем v2fly категории из групп
	for _, cfg := range config.Groups {
		v2flyCategories = append(v2flyCategories, cfg.V2fly...)
	}

	if len(v2flyCategories) > 0 {
		data, err := processV2flyCategories(ctx, v2flyCategories)
		if err != nil {
			logger.Warn("Error processing v2fly: %v", err)
		} else {
			for k, v := range data {
				v2flyData[k] = v
			}
		}
	}

	g, ctx := errgroup.WithContext(ctx)

	for name, cfg := range config.Services {
		// Сохраняем оригинальный регистр имени для создания папки
		originalName := name
		// Создаем нормализованное имя для внутреннего использования
		normalizedName := strings.ToLower(name)

		serviceGeneral[normalizedName] = getGeneralValue(cfg.General)
		name, cfg := originalName, cfg

		g.Go(func() error {
			domains, err := processDomainSources(ctx, cfg.URL, cfg.Domains, v2flyData, cfg.V2fly)
			if err != nil {
				logger.Warn("Error processing service %s: %v", name, err)
				domains = []string{}
			}

			// Создаем папку с оригинальным регистром
			servicePath := filepath.Join(categoriesDir, name, name+".lst")
			if err := saveDomains(servicePath, domains); err != nil {
				return fmt.Errorf("save service domains for %s: %w", name, err)
			}

			mu.Lock()
			// Сохраняем данные под нормализованным именем для поиска
			serviceDomains[normalizedName] = domains
			// Всегда сохраняем домены сервиса для возможной очистки, независимо от general
			serviceDomainsForCleanup[normalizedName] = domains

			if !getGeneralValue(cfg.General) {
				for _, d := range domains {
					allExcluded[d] = struct{}{}
				}
			}
			mu.Unlock()

			logger.Info("Processed service %s: %d domains", name, len(domains))
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, nil, nil, nil, nil, err
	}

	excludedList := make([]string, 0, len(allExcluded))
	for d := range allExcluded {
		excludedList = append(excludedList, d)
	}
	return serviceDomains, serviceGeneral, excludedList, v2flyData, serviceDomainsForCleanup, nil
}

func processGroup(ctx context.Context, name string, cfg GroupConfig, v2flyData map[string][]string, serviceDomains map[string][]string, serviceGeneral map[string]bool) ([]string, error) {
	domains, err := processDomainSources(ctx, cfg.URL, cfg.Domains, v2flyData, cfg.V2fly)
	if err != nil {
		return nil, err
	}

	domainSet := make(map[string]struct{})
	for _, d := range domains {
		domainSet[d] = struct{}{}
	}

	groupGeneralValue := getGeneralValue(cfg.General)

	for _, serviceName := range cfg.Include {
		// Приводим имя сервиса к нижнему регистру для поиска в serviceDomains
		normalizedServiceName := strings.ToLower(serviceName)
		if data, ok := serviceDomains[normalizedServiceName]; ok {
			// Проверяем приоритет: сервисы имеют приоритет над группами
			if serviceExists := serviceGeneral[normalizedServiceName]; serviceExists {
				// Всегда добавляем домены сервиса в группу, независимо от general
				for _, d := range data {
					domainSet[d] = struct{}{}
				}
			} else {
				// Если сервис не найден, используем настройку группы
				if groupGeneralValue {
					for _, d := range data {
						domainSet[d] = struct{}{}
					}
				}
			}
		} else {
			logger.Warn("Service not found: %s (normalized: %s)", serviceName, normalizedServiceName)
		}
	}

	domainList := make([]string, 0, len(domainSet))
	for d := range domainSet {
		domainList = append(domainList, d)
	}

	return filterDomains(domainList), nil
}

func processGroups(ctx context.Context, config Config, v2flyData map[string][]string, serviceDomains map[string][]string, serviceGeneral map[string]bool, excluded []string, serviceDomainsForCleanup map[string][]string) (map[string][]string, error) {
	excludedSet := make(map[string]struct{})
	for _, d := range excluded {
		excludedSet[d] = struct{}{}
	}

	groupResults := make(map[string][]string)
	g, ctx := errgroup.WithContext(ctx)
	var mu sync.Mutex

	for name, cfg := range config.Groups {
		// Сохраняем оригинальный регистр имени группы для создания папки
		originalName := name
		name, cfg := originalName, cfg

		g.Go(func() error {
			domains, err := processGroup(ctx, name, cfg, v2flyData, serviceDomains, serviceGeneral)
			if err != nil {
				logger.Warn("Error processing group %s: %v", name, err)
				domains = []string{} // Продолжаем с пустым списком
			}

			// Создаем папку с оригинальным регистром
			groupPath := filepath.Join(groupsDir, name, name+".lst")
			if err := saveDomains(groupPath, domains); err != nil {
				return fmt.Errorf("save group domains for %s: %w", name, err)
			}

			// Затем фильтруем для основного списка только если группа general = true
			var filtered []string
			if getGeneralValue(cfg.General) {
				filtered = make([]string, 0, len(domains))
				for _, d := range domains {
					if _, excluded := excludedSet[d]; !excluded {
						filtered = append(filtered, d)
					}
				}
			}

			mu.Lock()
			groupResults[name] = filtered
			mu.Unlock()

			logger.Info("Processed group %s: %d total domains, %d after exclusions, general=%t",
				name, len(domains), len(filtered), getGeneralValue(cfg.General))
			return nil
		})
	}

	if err := g.Wait(); err != nil {
		return nil, err
	}
	return groupResults, nil
}

func cleanupDomainsFromMainFile(serviceDomainsForCleanup map[string][]string, serviceGeneral map[string]bool, existingDomains map[string]struct{}) map[string]struct{} {
	// Создаем множество доменов сервисов с general=false для удаления
	domainsToRemove := make(map[string]struct{})

	for serviceName, domains := range serviceDomainsForCleanup {
		if !serviceGeneral[serviceName] { // Если сервис имеет general=false
			for _, domain := range domains {
				domainsToRemove[domain] = struct{}{}
			}
		}
	}

	// Удаляем домены сервисов с general=false из существующих доменов
	cleanedDomains := make(map[string]struct{})
	for domain := range existingDomains {
		if _, shouldRemove := domainsToRemove[domain]; !shouldRemove {
			cleanedDomains[domain] = struct{}{}
		}
	}

	logger.Info("Cleaned up %d domains from main file (services with general=false)",
		len(existingDomains)-len(cleanedDomains))

	return cleanedDomains
}

func loadConfig() (Config, error) {
	var config Config
	data, err := os.ReadFile(configPath)
	if err != nil {
		return config, fmt.Errorf("read config: %w", err)
	}

	if err := toml.Unmarshal(data, &config); err != nil {
		return config, fmt.Errorf("parse config: %w", err)
	}
	return config, nil
}

func loadExistingDomains() (map[string]struct{}, error) {
	existing := make(map[string]struct{})
	if _, err := os.Stat(domainsFile); os.IsNotExist(err) {
		return existing, nil
	}

	data, err := os.ReadFile(domainsFile)
	if err != nil {
		return nil, fmt.Errorf("read domains file: %w", err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			existing[line] = struct{}{}
		}
	}
	return existing, scanner.Err()
}

func buildMainDomainList(
	serviceDomains map[string][]string,
	serviceGeneral map[string]bool,
	groupDomains map[string][]string,
	existingDomains map[string]struct{},
	serviceDomainsForCleanup map[string][]string,
) map[string]struct{} {
	// Сначала очищаем существующие домены от доменов сервисов с general=false
	cleanedExistingDomains := cleanupDomainsFromMainFile(serviceDomainsForCleanup, serviceGeneral, existingDomains)

	mainDomains := make(map[string]struct{})

	// Добавляем очищенные существующие домены
	for d := range cleanedExistingDomains {
		mainDomains[d] = struct{}{}
	}

	// Добавляем домены сервисов с general=true
	for name, domains := range serviceDomains {
		if serviceGeneral[name] {
			for _, d := range domains {
				mainDomains[d] = struct{}{}
			}
		}
	}

	// Добавляем домены групп
	for _, domains := range groupDomains {
		for _, d := range domains {
			mainDomains[d] = struct{}{}
		}
	}

	return mainDomains
}

func excludeDomains(mainDomains map[string]struct{}, excluded []string) []string {
	if len(excluded) == 0 {
		result := make([]string, 0, len(mainDomains))
		for d := range mainDomains {
			result = append(result, d)
		}
		return result
	}

	// Создаем trie для исключений
	excludeTrie := newDomainTrie()
	for _, ex := range excluded {
		excludeTrie.insert(ex)
	}

	finalList := make([]string, 0, len(mainDomains))
	for d := range mainDomains {
		if !excludeTrie.containsSuperdomain(d) {
			finalList = append(finalList, d)
		}
	}
	return finalList
}

func saveDomainsFile(domains []string) error {
	filtered := filterDomains(domains)
	data := strings.Join(filtered, "\n") + "\n"
	return os.WriteFile(domainsFile, []byte(data), 0644)
}

func main() {
	logger.Info("Starting domain parser...")
	startTime := time.Now()
	defer func() {
		logger.Info("Execution time: %v", time.Since(startTime))
	}()

	if err := runDomainScripts(); err != nil {
		logger.Error("Domain scripts error: %v", err)
		os.Exit(1)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	defer func() {
		if err := os.RemoveAll(v2flyCloneDir); err != nil {
			logger.Warn("Error cleaning v2fly dir: %v", err)
		}
	}()

	config, err := loadConfig()
	if err != nil {
		logger.Error("Config error: %v", err)
		os.Exit(1)
	}

	// Исправленный вызов processServices с дополнительным возвратом
	serviceDomains, serviceGeneral, allExcluded, v2flyData, serviceDomainsForCleanup, err := processServices(ctx, config)
	if err != nil {
		logger.Error("Services processing error: %v", err)
		os.Exit(1)
	}

	// Передаем serviceDomainsForCleanup в processGroups
	groupDomains, err := processGroups(ctx, config, v2flyData, serviceDomains, serviceGeneral, allExcluded, serviceDomainsForCleanup)
	if err != nil {
		logger.Error("Groups processing error: %v", err)
		os.Exit(1)
	}

	existingDomains, err := loadExistingDomains()
	if err != nil {
		logger.Error("Error loading existing domains: %v", err)
		os.Exit(1)
	}

	// Передаем serviceDomainsForCleanup в buildMainDomainList
	mainDomains := buildMainDomainList(
		serviceDomains,
		serviceGeneral,
		groupDomains,
		existingDomains,
		serviceDomainsForCleanup,
	)

	finalDomains := excludeDomains(mainDomains, allExcluded)

	if err := saveDomainsFile(finalDomains); err != nil {
		logger.Error("Error saving domains file: %v", err)
		os.Exit(1)
	}

	logger.Info("Domain processing completed successfully")
}
