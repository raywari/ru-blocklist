package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
)

// Конфигурационные пути
const (
	MainDomainsFile    = "data/domains/domains-summary.lst"
	SourcesList        = "scripts/sources/domains.txt"
	OutputDir          = "data/compared-domains"
	YouTubeDomainsFile = "data/domains/services/YouTube/YouTube.lst"
	NonYouTubeOutput   = "data/domains/domains-summary-no-yt.lst"
)

// LeveledLogger обеспечивает структурированное логирование
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

// DomainProcessor обрабатывает домены
type DomainProcessor struct {
	re1          *regexp.Regexp
	re2          *regexp.Regexp
	re3          *regexp.Regexp
	re4          *regexp.Regexp
	re5          *regexp.Regexp
	re6          *regexp.Regexp
	domainPattern *regexp.Regexp
}

// NewDomainProcessor создает новый процессор доменов
func NewDomainProcessor() *DomainProcessor {
	logger.Info("Creating new DomainProcessor")
	return &DomainProcessor{
		re1:          regexp.MustCompile(`^\s*-\s*`),
		re2:          regexp.MustCompile(`^\s*(#|;|//|--).*`),
		re3:          regexp.MustCompile(`^full:`),
		re4:          regexp.MustCompile(`^(https?://|//)`),
		re5:          regexp.MustCompile(`[/:].*$`),
		re6:          regexp.MustCompile(`^www[2-9]?\.`),
		domainPattern: regexp.MustCompile(`^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}`),
	}
}

// CleanLine очищает строку
func (dp *DomainProcessor) CleanLine(line string) string {
	return strings.TrimSpace(
		dp.re6.ReplaceAllString(
			dp.re5.ReplaceAllString(
				dp.re4.ReplaceAllString(
					dp.re3.ReplaceAllString(
						dp.re2.ReplaceAllString(
							dp.re1.ReplaceAllString(line, ""),
							""),
						""),
					""),
				""),
			""),
	)
}

// ReadLines читает и очищает строки из файла
func (dp *DomainProcessor) ReadLines(filePath string) ([]string, error) {
	logger.Info("Reading lines from: %s", filePath)
	file, err := os.Open(filePath)
	if err != nil {
		logger.Error("Error opening file %s: %v", filePath, err)
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		cleaned := dp.CleanLine(scanner.Text())
		if cleaned != "" {
			lines = append(lines, cleaned)
		}
	}
	
	if err := scanner.Err(); err != nil {
		logger.Error("Scanner error for %s: %v", filePath, err)
		return nil, err
	}
	
	logger.Info("Read %d lines from %s", len(lines), filePath)
	return lines, nil
}

// WriteLines записывает строки в файл
func (dp *DomainProcessor) WriteLines(filePath string, lines []string) error {
	logger.Info("Writing %d lines to: %s", len(lines), filePath)
	
	if len(lines) == 0 {
		logger.Warn("No lines to write to %s, creating empty file", filePath)
		return os.WriteFile(filePath, []byte{}, 0644)
	}

	seen := make(map[string]struct{})
	unique := make([]string, 0, len(lines))
	for _, v := range lines {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			unique = append(unique, v)
		}
	}

	sort.Strings(unique)
	content := strings.Join(unique, "\n") + "\n"
	
	if err := os.WriteFile(filePath, []byte(content), 0644); err != nil {
		logger.Error("Error writing to %s: %v", filePath, err)
		return err
	}
	
	logger.Info("Successfully wrote %d unique lines to %s", len(unique), filePath)
	return nil
}

// FilterSubdomains фильтрует поддомены
func (dp *DomainProcessor) FilterSubdomains(domains []string) []string {
	logger.Info("Filtering subdomains from %d domains", len(domains))
	
	sort.Slice(domains, func(i, j int) bool {
		return strings.Count(domains[i], ".") < strings.Count(domains[j], ".")
	})

	keep := make(map[string]bool)
	var filtered []string

	for _, domain := range domains {
		parts := strings.Split(domain, ".")
		found := false

		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[i:], ".")
			if keep[parent] {
				found = true
				break
			}
		}

		if !found {
			filtered = append(filtered, domain)
			keep[domain] = true
		}
	}

	sort.Strings(filtered)
	logger.Info("Filtered %d domains to %d unique parents", len(domains), len(filtered))
	return filtered
}

// CompareFiles сравнивает два списка доменов
func (dp *DomainProcessor) CompareFiles(list1, list2 []string) (only1, only2, common []string) {
	logger.Info("Comparing %d vs %d domains", len(list1), len(list2))
	
	i, j := 0, 0
	for i < len(list1) && j < len(list2) {
		cmp := strings.Compare(list1[i], list2[j])
		switch {
		case cmp < 0:
			only1 = append(only1, list1[i])
			i++
		case cmp > 0:
			only2 = append(only2, list2[j])
			j++
		default:
			common = append(common, list1[i])
			i++
			j++
		}
	}

	only1 = append(only1, list1[i:]...)
	only2 = append(only2, list2[j:]...)
	
	logger.Info("Comparison results: only1=%d, only2=%d, common=%d", 
		len(only1), len(only2), len(common))
	return
}

// DomainComparator сравнивает домены
type DomainComparator struct {
	*DomainProcessor
	sourcesPath   string
	outputDir     string
	primaryDomains map[string]bool
}

// NewDomainComparator создает компаратор
func NewDomainComparator(sourcesPath, outputDir string) *DomainComparator {
	logger.Info("Creating DomainComparator with sources: %s, output: %s", 
		sourcesPath, outputDir)
		
	return &DomainComparator{
		DomainProcessor: NewDomainProcessor(),
		sourcesPath:     sourcesPath,
		outputDir:       outputDir,
		primaryDomains:  make(map[string]bool),
	}
}

// ProcessExternalSource обрабатывает внешний источник
func (dc *DomainComparator) ProcessExternalSource(url string) []string {
	logger.Info("Processing external source: %s", url)
	
	resp, err := http.Get(url)
	if err != nil {
		logger.Error("Error fetching URL %s: %v", url, err)
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		logger.Warn("URL %s returned status: %s", url, resp.Status)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		logger.Error("Error reading body from %s: %v", url, err)
		return nil
	}

	content := regexp.MustCompile(`(?m)^\s*#.*$|^\s*$|^[0-9.]+\s+`).ReplaceAll(body, []byte{})
	content = regexp.MustCompile(`\s+`).ReplaceAll(content, []byte("\n"))

	var domains []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		cleaned := dc.CleanLine(scanner.Text())
		if cleaned == "" || !dc.domainPattern.MatchString(cleaned) {
			continue
		}

		parts := strings.Split(cleaned, ".")
		skip := false
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[i:], ".")
			if dc.primaryDomains[parent] {
				skip = true
				break
			}
		}

		if !skip {
			domains = append(domains, cleaned)
		}
	}

	seen := make(map[string]struct{})
	var unique []string
	for _, d := range domains {
		if _, exists := seen[d]; !exists {
			seen[d] = struct{}{}
			unique = append(unique, d)
		}
	}

	sort.Strings(unique)
	logger.Info("Processed %d domains from %s", len(unique), url)
	return unique
}

// GenerateReports генерирует отчеты
func (dc *DomainComparator) GenerateReports(sourceURL string, externalDomains, primarySorted []string) {
	onlyInExternal, _, common := dc.CompareFiles(externalDomains, primarySorted)

	reports := map[string][]string{
		"missing":  onlyInExternal,
		"presence": common,
	}

	for reportType, data := range reports {
		if len(data) == 0 {
			logger.Info("Skipping empty report: %s for %s", reportType, sourceURL)
			continue
		}

		reportFile := filepath.Join(dc.outputDir, reportType+"-domains.txt")
		f, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logger.Error("Error opening report file %s: %v", reportFile, err)
			continue
		}
		defer f.Close()

		_, err = f.WriteString(fmt.Sprintf("# %s domains\n", strings.Title(reportType)))
		if err != nil {
			logger.Error("Error writing header to %s: %v", reportFile, err)
		}
		
		_, err = f.WriteString(fmt.Sprintf("# Source: %s\n\n", sourceURL))
		if err != nil {
			logger.Error("Error writing source to %s: %v", reportFile, err)
		}
		
		for _, domain := range data {
			_, err := f.WriteString(fmt.Sprintf("- %s\n", domain))
			if err != nil {
				logger.Error("Error writing domain to %s: %v", reportFile, err)
				break
			}
		}
		
		_, err = f.WriteString("\n")
		if err != nil {
			logger.Error("Error writing footer to %s: %v", reportFile, err)
		}
		
		logger.Info("Generated %s report for %s with %d domains", 
			reportType, sourceURL, len(data))
	}
}

// ProcessSources обрабатывает источники
func (dc *DomainComparator) ProcessSources(primaryDomains []string) error {
	logger.Info("Processing sources with %d primary domains", len(primaryDomains))
	
	// Удаление старых отчетов
	if err := os.Remove(filepath.Join(dc.outputDir, "missing-domains.txt")); err != nil && !os.IsNotExist(err) {
		logger.Warn("Error removing missing-domains.txt: %v", err)
	}
	if err := os.Remove(filepath.Join(dc.outputDir, "presence-domains.txt")); err != nil && !os.IsNotExist(err) {
		logger.Warn("Error removing presence-domains.txt: %v", err)
	}

	// Чтение списка источников
	file, err := os.Open(dc.sourcesPath)
	if err != nil {
		logger.Error("Error opening sources list %s: %v", dc.sourcesPath, err)
		return err
	}
	defer file.Close()

	var sourceURLs []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		sourceURLs = append(sourceURLs, strings.Split(line, "#")[0])
	}
	
	if err := scanner.Err(); err != nil {
		logger.Error("Error reading sources list: %v", err)
		return err
	}

	logger.Info("Found %d sources to process", len(sourceURLs))

	// Инициализация основного списка доменов
	for _, domain := range primaryDomains {
		dc.primaryDomains[domain] = true
	}
	primarySorted := make([]string, len(primaryDomains))
	copy(primarySorted, primaryDomains)
	sort.Strings(primarySorted)

	// Параллельная обработка
	var wg sync.WaitGroup
	var mu sync.Mutex
	for _, url := range sourceURLs {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			logger.Info("Processing source: %s", u)
			externalDomains := dc.ProcessExternalSource(u)
			if len(externalDomains) > 0 {
				mu.Lock()
				dc.GenerateReports(u, externalDomains, primarySorted)
				mu.Unlock()
			} else {
				logger.Warn("No domains processed for source: %s", u)
			}
		}(url)
	}
	wg.Wait()

	logger.Info("Finished processing %d sources", len(sourceURLs))
	return nil
}

func main() {
	logger.Info("Starting domain processing")
	dp := NewDomainProcessor()

	// Обработка основного файла доменов
	domains, err := dp.ReadLines(MainDomainsFile)
	if err != nil {
		logger.Error("Fatal error reading main domains: %v", err)
		os.Exit(1)
	}

	filteredDomains := dp.FilterSubdomains(domains)
	if err := dp.WriteLines(MainDomainsFile, filteredDomains); err != nil {
		logger.Error("Fatal error writing filtered domains: %v", err)
		os.Exit(1)
	}

	// Создание выходного каталога
	logger.Info("Creating output directory: %s", OutputDir)
	if err := os.MkdirAll(OutputDir, 0755); err != nil {
		logger.Error("Fatal error creating output dir: %v", err)
		os.Exit(1)
	}

	// Сравнение с внешними источниками
	comparator := NewDomainComparator(SourcesList, OutputDir)
	if err := comparator.ProcessSources(filteredDomains); err != nil {
		logger.Error("Fatal error processing sources: %v", err)
		os.Exit(1)
	}

	// Фильтрация YouTube доменов
	logger.Info("Filtering YouTube domains")
	ytDomains, err := dp.ReadLines(YouTubeDomainsFile)
	if err != nil {
		logger.Error("Fatal error reading YouTube domains: %v", err)
		os.Exit(1)
	}

	ytSet := make(map[string]bool)
	for _, d := range ytDomains {
		ytSet[d] = true
	}

	var nonYT []string
	for _, d := range filteredDomains {
		if !ytSet[d] {
			nonYT = append(nonYT, d)
		}
	}

	if err := dp.WriteLines(NonYouTubeOutput, nonYT); err != nil {
		logger.Error("Fatal error writing non-YouTube domains: %v", err)
		os.Exit(1)
	}

	logger.Info("Domain processing completed successfully")
}