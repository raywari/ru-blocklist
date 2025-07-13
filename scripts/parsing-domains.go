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
	General *bool    `toml:"general,omitempty"`
}

type GroupConfig struct {
	Include []string `toml:"include"`
	URL     []string `toml:"url"`
	Domains []string `toml:"domains"`
	V2fly   []string `toml:"v2fly"`
	General *bool    `toml:"general,omitempty"`
}

func getGeneralValue(general *bool) bool {
	if general == nil {
		return true
	}
	return *general
}

func runDomainScripts() error {

	scriptDir, err := filepath.Abs("scripts/config/domains-scripts")
	if err != nil {
		return fmt.Errorf("get absolute path: %w", err)
	}

	logger.Info("Running domain scripts in %s", scriptDir)


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


	originalDir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("get current directory: %w", err)
	}
	defer os.Chdir(originalDir)

	if err := os.Chdir(scriptDir); err != nil {
		return fmt.Errorf("change to scripts directory: %w", err)
	}

	for _, file := range goFiles {

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


var domainSlicePool = sync.Pool{
	New: func() interface{} {
		return make([]string, 0, 10)
	},
}


var (
	compiledRegexes = struct {
		sync.RWMutex
		cache map[string]*regexp.Regexp
	}{
		cache: make(map[string]*regexp.Regexp),
	}


	tldInText        = regexp.MustCompile(`\.([a-zA-Z]{2,})`)
	cleanupRegex     = regexp.MustCompile(`\([^)]*\)`)
	symbolClassRegex = regexp.MustCompile(`\[[^\]]*\]`)
	braceRegex       = regexp.MustCompile(`\{[^}]*\}`)
	finalDomainRegex = regexp.MustCompile(`[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+(\.[a-zA-Z0-9-]+)*`)


	dotPlusRegex      = regexp.MustCompile(`\.(.+?)\\\.`)
	awsPatternRegex   = regexp.MustCompile(`\\\.(.+?)\\\.`)
	numericRangeRegex = regexp.MustCompile(`\[0-9\]`)
	letterRangeRegex  = regexp.MustCompile(`\[a-e0-9\]`)
	dashNumericRegex  = regexp.MustCompile(`-\[0-9\]\[0-9\]`)
	dashLetterRegex   = regexp.MustCompile(`-\[a-e0-9\]`)


	domainPartRegex   = regexp.MustCompile(`^[a-zA-Z0-9-]+$`)
	tldLetterRegex    = regexp.MustCompile(`[a-zA-Z]`)
	tldValidRegex     = regexp.MustCompile(`^[a-zA-Z]+$`)
	invalidCharsRegex = regexp.MustCompile(`[()[\]{}|+*?$\\^]`)


	standardRegex      = regexp.MustCompile(`([a-zA-Z0-9-]+(?:\[[^\]]*\])*[a-zA-Z0-9-]*)\\?\.\(([^)]+)\)`)
	domainRegex        = regexp.MustCompile(`[a-zA-Z0-9-]+\.[a-zA-Z]{2,}`)
	altRegex           = regexp.MustCompile(`([a-zA-Z0-9-]+)\\?\.\([^)]+\)`)
	rangeRegex         = regexp.MustCompile(`([a-zA-Z0-9-]+)\[([0-9-]+)\]([a-zA-Z0-9-]*)\\\.\(([^)]+)\)`)
	specificRangeRegex = regexp.MustCompile(`([a-zA-Z0-9-]+)\[([1-9])\]([a-zA-Z0-9-]*)\\\.\(([^)]+)\)`)
	patternWithPrefix  = regexp.MustCompile(`\[([^\]]+)\]([?+*]?)([a-zA-Z0-9-]+)`)
	tldInBrackets      = regexp.MustCompile(`\(([^)]+)\)`)
	complexRegex       = regexp.MustCompile(`([a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*)`)
	awsRegex           = regexp.MustCompile(`([a-zA-Z0-9-]+)\.amazonaws\.com`)
	awsdnsRegex        = regexp.MustCompile(`awsdns(?:-[a-zA-Z0-9]+)*\.([a-zA-Z]{2,})`)


	baseRegexes = []*regexp.Regexp{
		regexp.MustCompile(`\[1-9\]\+`),
		regexp.MustCompile(`\[0-9\]\+`),
		regexp.MustCompile(`\[a-z\]\?`),
		regexp.MustCompile(`\[A-Z\]\?`),
		regexp.MustCompile(`\[[^\]]+\]`),
		regexp.MustCompile(`[+*?]`),
	}

	baseReplacements = []string{"1", "0", "a", "A", "x", ""}
)


var domainValidationCache = struct {
	sync.RWMutex
	cache map[string]bool
}{
	cache: make(map[string]bool),
}

func handleRegexPattern(pattern string) ([]string, error) {

	if idx := strings.Index(pattern, " @"); idx != -1 {
		pattern = pattern[:idx]
	}


	domains := extractDomainsFromRegex(pattern)
	if len(domains) > 0 {
		return domains, nil
	}


	return nil, nil
}

func extractDomainsFromRegex(pattern string) []string {

	domains := domainSlicePool.Get().([]string)
	domains = domains[:0]

	defer func() {

		if cap(domains) <= 100 {
			domainSlicePool.Put(domains)
		}
	}()





	if standardDomains := extractFromStandardRegexPattern(pattern); len(standardDomains) > 0 {
		domains = append(domains, standardDomains...)
	}


	if altDomains := extractFromAlternativePattern(pattern); len(altDomains) > 0 {
		domains = append(domains, altDomains...)
	}


	if rangeDomains := extractFromRangePattern(pattern); len(rangeDomains) > 0 {
		domains = append(domains, rangeDomains...)
	}


	if simpleDomains := extractFromSimplePattern(pattern); len(simpleDomains) > 0 {
		domains = append(domains, simpleDomains...)
	}


	if len(domains) == 0 {
		if complexDomains := extractFromComplexPatterns(pattern); len(complexDomains) > 0 {
			domains = append(domains, complexDomains...)
		}
	}


	if len(domains) == 0 {
		if literalDomains := extractFromLiteralDomains(pattern); len(literalDomains) > 0 {
			domains = append(domains, literalDomains...)
		}
	}


	result := validateAndCleanDomains(domains)


	finalResult := make([]string, len(result))
	copy(finalResult, result)

	return finalResult
}

func extractFromStandardRegexPattern(pattern string) []string {
	var domains []string

	matches := standardRegex.FindAllStringSubmatch(pattern, -1)

	for _, match := range matches {
		if len(match) >= 3 {
			domainPart := match[1]
			tldPart := match[2]

			baseDomain := extractBaseDomainFromPattern(domainPart)
			if baseDomain == "" || len(baseDomain) < 2 {
				continue
			}


			if isValidTLD(baseDomain) {
				continue
			}

			tlds := strings.Split(tldPart, "|")

			for _, tld := range tlds {
				tld = strings.TrimSpace(tld)

				if isValidTLD(tld) {
					domain := baseDomain + "." + tld
					if isValidDomainCached(domain) && !isInvalidDomain(domain) {
						domains = append(domains, strings.ToLower(domain))
					}
				}
			}
		}
	}

	return domains
}

func extractBaseDomainFromPattern(pattern string) string {

	result := pattern

	for i, regex := range baseRegexes {
		result = regex.ReplaceAllString(result, baseReplacements[i])
	}


	result = strings.ReplaceAll(result, `\`, "")


	if domainPartRegex.MatchString(result) {
		return result
	}

	return ""
}

func extractFromSimplePattern(pattern string) []string {
	var domains []string

	matches := domainRegex.FindAllString(pattern, -1)

	for _, match := range matches {

		cleanMatch := strings.ReplaceAll(match, `\`, "")

		if isValidDomainCached(cleanMatch) && !isInvalidDomain(cleanMatch) {
			domains = append(domains, strings.ToLower(cleanMatch))
		}
	}

	return domains
}

func extractFromAlternativePattern(pattern string) []string {
	var domains []string

	matches := altRegex.FindAllStringSubmatch(pattern, -1)

	for _, match := range matches {
		if len(match) > 1 {
			baseDomain := match[1]
			fullMatch := match[0]


			if altStartIndex := strings.Index(fullMatch, "("); altStartIndex != -1 {
				if altEndIndex := strings.LastIndex(fullMatch, ")"); altEndIndex > altStartIndex {
					altPart := fullMatch[altStartIndex+1 : altEndIndex]
					altPart = strings.ReplaceAll(altPart, `\.`, ".")

					if strings.Contains(altPart, "|") {
						alternatives := strings.Split(altPart, "|")
						for _, alt := range alternatives {
							cleanAlt := invalidCharsRegex.ReplaceAllString(alt, "")

							var domain string
							if strings.HasPrefix(cleanAlt, ".") {
								domain = baseDomain + cleanAlt
							} else {
								domain = baseDomain + "." + cleanAlt
							}

							if isValidDomainCached(domain) {
								domains = append(domains, strings.ToLower(domain))
							}
						}
					}
				}
			}
		}
	}

	return domains
}

func extractFromRangePattern(pattern string) []string {
	var domains []string


	matches := rangeRegex.FindAllStringSubmatch(pattern, -1)
	for _, match := range matches {
		if len(match) > 4 {
			domain := fmt.Sprintf("%s1.%s", match[1], match[4])
			if isValidDomainCached(domain) {
				domains = append(domains, strings.ToLower(domain))
			}
		}
	}


	matches = specificRangeRegex.FindAllStringSubmatch(pattern, -1)
	for _, match := range matches {
		if len(match) > 4 {
			domain := fmt.Sprintf("%s1.%s", match[1], match[4])
			if isValidDomainCached(domain) {
				domains = append(domains, strings.ToLower(domain))
			}
		}
	}


	matches = patternWithPrefix.FindAllStringSubmatch(pattern, -1)
	for _, match := range matches {
		if len(match) > 3 {
			charClass := match[1]
			quantifier := match[2]
			baseName := match[3]

			prefix := getPrefixForCharClass(charClass, quantifier)
			domain := prefix + baseName


			tldMatches := tldInBrackets.FindAllStringSubmatch(pattern, -1)
			if len(tldMatches) > 0 {
				tldPart := tldMatches[0][1]
				tlds := strings.Split(tldPart, "|")

				for _, tld := range tlds {
					if isValidTLD(tld) {
						fullDomain := domain + "." + tld
						if isValidDomainCached(fullDomain) {
							domains = append(domains, strings.ToLower(fullDomain))
						}
					}
				}
			}
		}
	}

	return domains
}

func getPrefixForCharClass(charClass, quantifier string) string {
	switch {
	case strings.Contains(charClass, "1-9"):
		return "1"
	case strings.Contains(charClass, "0-9"):
		return "0"
	case strings.Contains(charClass, "a-z"):
		if quantifier == "?" {
			return ""
		}
		return "a"
	case strings.Contains(charClass, "A-Z"):
		if quantifier == "?" {
			return ""
		}
		return "A"
	case strings.Contains(charClass, "a-e0-9"):
		return "a"
	default:
		return "x"
	}
}

func extractFromAWSPatterns(pattern string) []string {
	var domains []string


	if strings.Contains(pattern, "amazonaws.com") {
		matches := awsRegex.FindAllStringSubmatch(pattern, -1)
		for _, match := range matches {
			if len(match) > 1 {
				domain := match[1] + ".amazonaws.com"
				if isValidDomainCached(domain) {
					domains = append(domains, strings.ToLower(domain))
				}
			}
		}

		if len(domains) == 0 {
			domains = append(domains, "amazonaws.com")
		}
	}


	if strings.Contains(pattern, "awsdns") {
		matches := awsdnsRegex.FindAllStringSubmatch(pattern, -1)
		for _, match := range matches {
			if len(match) > 2 {
				domain := "awsdns." + match[2]
				if isValidDomainCached(domain) {
					domains = append(domains, strings.ToLower(domain))
				}
			}
		}
	}

	return domains
}

func extractFromComplexPatterns(pattern string) []string {
	var domains []string

	matches := complexRegex.FindAllStringSubmatch(pattern, -1)

	for _, match := range matches {
		if len(match) > 1 {
			baseDomain := strings.TrimRight(match[1], ".-")


			if strings.Contains(pattern, `.+`) {

				domainParts := extractDomainPartsFromDotPlus(pattern)
				for _, part := range domainParts {
					if tldDomains := buildDomainsWithTLD(part, pattern); len(tldDomains) > 0 {
						domains = append(domains, tldDomains...)
					}
				}
			}


			if tldDomains := buildDomainsWithTLD(baseDomain, pattern); len(tldDomains) > 0 {
				domains = append(domains, tldDomains...)
			}
		}
	}

	return domains
}


func extractDomainPartsFromDotPlus(pattern string) []string {
	var parts []string


	if strings.Contains(pattern, "amazonaws") {
		parts = append(parts, "amazonaws")
	}


	if strings.Contains(pattern, "awsdns") {

		awsPart := "awsdns"


		if dashNumericRegex.MatchString(pattern) {
			awsPart = "awsdns-01"
		}


		if strings.Contains(pattern, "awsdns-cn") {
			awsPart = "awsdns-cn-01"
		}


		if strings.Contains(pattern, "awsdns-cn") && letterRangeRegex.MatchString(pattern) {
			awsPart = "awsdns-cn-0a"
		}

		parts = append(parts, awsPart)
	}


	if strings.Contains(pattern, "amzndns") {
		parts = append(parts, "amzndns")
	}


	dotPlusMatches := dotPlusRegex.FindAllStringSubmatch(pattern, -1)
	for _, match := range dotPlusMatches {
		if len(match) > 1 {
			part := match[1]

			cleanPart := strings.ReplaceAll(part, `\`, "")
			cleanPart = numericRangeRegex.ReplaceAllString(cleanPart, "0")
			cleanPart = letterRangeRegex.ReplaceAllString(cleanPart, "a")
			cleanPart = regexp.MustCompile(`\[[^\]]+\]`).ReplaceAllString(cleanPart, "x")

			if cleanPart != "" && len(cleanPart) > 1 {
				parts = append(parts, cleanPart)
			}
		}
	}

	return parts
}


func buildDomainsWithTLD(baseDomain, pattern string) []string {
	var domains []string


	if isValidTLD(baseDomain) || len(baseDomain) < 2 {
		return domains
	}


	tldMatches := tldInBrackets.FindAllStringSubmatch(pattern, -1)
	if len(tldMatches) > 0 {
		tldPart := tldMatches[0][1]
		tlds := strings.Split(tldPart, "|")

		for _, tld := range tlds {
			tld = strings.TrimSpace(tld)
			if isValidTLD(tld) {

				if strings.Contains(pattern, ".+") {
					domain := "example." + baseDomain + "." + tld
					if isValidDomainCached(domain) && !isInvalidDomain(domain) {
						domains = append(domains, strings.ToLower(domain))
					}
				}


				domain := baseDomain + "." + tld
				if isValidDomainCached(domain) && !isInvalidDomain(domain) {
					domains = append(domains, strings.ToLower(domain))
				}
			}
		}
	} else {

		tldMatches := tldInText.FindAllStringSubmatch(pattern, -1)
		if len(tldMatches) > 0 {
			tld := tldMatches[len(tldMatches)-1][1]

			if isValidTLD(tld) {

				if strings.Contains(pattern, ".+") {
					domain := "example." + baseDomain + "." + tld
					if isValidDomainCached(domain) && !isInvalidDomain(domain) {
						domains = append(domains, strings.ToLower(domain))
					}
				}


				domain := baseDomain + "." + tld
				if isValidDomainCached(domain) && !isInvalidDomain(domain) {
					domains = append(domains, strings.ToLower(domain))
				}
			}
		}
	}

	return domains
}

func extractFromLiteralDomains(pattern string) []string {
	var domains []string


	cleaned := pattern


	cleaned = strings.ReplaceAll(cleaned, `(^|\.)`, "")
	cleaned = strings.ReplaceAll(cleaned, `^`, "")
	cleaned = strings.ReplaceAll(cleaned, `$`, "")


	cleaned = strings.ReplaceAll(cleaned, `.+`, "PLACEHOLDER")
	cleaned = strings.ReplaceAll(cleaned, `.*`, "PLACEHOLDER")
	cleaned = strings.ReplaceAll(cleaned, `+`, "")
	cleaned = strings.ReplaceAll(cleaned, `?`, "")
	cleaned = strings.ReplaceAll(cleaned, `*`, "")


	cleaned = cleanupRegex.ReplaceAllString(cleaned, "")
	cleaned = strings.ReplaceAll(cleaned, `|`, " ")


	cleaned = symbolClassRegex.ReplaceAllString(cleaned, "1")
	cleaned = braceRegex.ReplaceAllString(cleaned, "")


	cleaned = strings.ReplaceAll(cleaned, `\`, "")


	cleaned = strings.ReplaceAll(cleaned, "PLACEHOLDER", "example")


	matches := finalDomainRegex.FindAllString(cleaned, -1)

	for _, match := range matches {
		match = strings.Trim(match, ".-")
		if isValidDomainCached(match) && !isInvalidDomain(match) {
			domains = append(domains, strings.ToLower(match))
		}
	}

	return domains
}

func isValidDomainCached(domain string) bool {

	domainValidationCache.RLock()
	if result, exists := domainValidationCache.cache[domain]; exists {
		domainValidationCache.RUnlock()
		return result
	}
	domainValidationCache.RUnlock()


	result := isValidDomain(domain)


	domainValidationCache.Lock()

	if len(domainValidationCache.cache) < 10000 {
		domainValidationCache.cache[domain] = result
	}
	domainValidationCache.Unlock()

	return result
}

func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}


	if !strings.Contains(domain, ".") {
		return false
	}

	if invalidCharsRegex.MatchString(domain) {
		return false
	}

	if strings.HasPrefix(domain, "-") || strings.HasSuffix(domain, "-") ||
		strings.HasPrefix(domain, ".") || strings.HasSuffix(domain, ".") {
		return false
	}


	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return false
	}

	for _, part := range parts {
		if len(part) == 0 || len(part) > 63 {
			return false
		}
		if strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
		if !domainPartRegex.MatchString(part) {
			return false
		}
	}


	tld := parts[len(parts)-1]
	if !tldLetterRegex.MatchString(tld) || len(tld) < 2 {
		return false
	}


	if len(parts) == 2 && isValidTLD(parts[0]) {
		return false
	}

	return true
}

func isValidTLD(tld string) bool {
	if len(tld) < 2 || len(tld) > 10 {
		return false
	}


	tlds, err := loadTLDs()
	if err != nil {

		return tldValidRegex.MatchString(tld)
	}


	_, exists := tlds[strings.ToUpper(tld)]
	return exists
}

var (
	tlds     map[string]struct{}
	tldsOnce sync.Once
	tldsErr  error
)

func loadTLDs() (map[string]struct{}, error) {
	tldsOnce.Do(func() {
		tlds = make(map[string]struct{})


		tldURL := "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"


		resp, err := http.Get(tldURL)
		if err != nil {
			tldsErr = fmt.Errorf("failed to download TLD list: %w", err)
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			tldsErr = fmt.Errorf("unexpected status code: %d", resp.StatusCode)
			return
		}

		scanner := bufio.NewScanner(resp.Body)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			tlds[line] = struct{}{}
		}

		if err := scanner.Err(); err != nil {
			tldsErr = fmt.Errorf("error reading TLD list: %w", err)
			return
		}
	})

	return tlds, tldsErr
}


func isInvalidDomain(domain string) bool {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return true
	}


	if len(parts) == 2 {
		first := parts[0]
		second := parts[1]


		if isValidTLD(first) && isValidTLD(second) {
			return true
		}


		if len(first) <= 3 && isValidTLD(first) {
			return true
		}
	}


	for i, part := range parts {
		if len(part) == 1 && i != len(parts)-1 {

			if part != "a" && part != "b" && part != "c" && part != "d" &&
				part != "e" && part != "f" && part != "g" && part != "h" &&
				part != "i" && part != "j" && part != "k" && part != "l" &&
				part != "m" && part != "n" && part != "o" && part != "p" &&
				part != "q" && part != "r" && part != "s" && part != "t" &&
				part != "u" && part != "v" && part != "w" && part != "x" &&
				part != "y" && part != "z" {
				return true
			}
		}
	}

	return false
}

func validateAndCleanDomains(domains []string) []string {
	if len(domains) == 0 {
		return nil
	}


	seen := make(map[string]bool, len(domains))
	var validDomains []string

	for _, domain := range domains {
		if !seen[domain] && isValidDomainCached(domain) {
			seen[domain] = true
			validDomains = append(validDomains, domain)
		}
	}

	return validDomains
}


func unique(slice []string) []string {
	keys := make(map[string]bool)
	var result []string

	for _, item := range slice {
		if !keys[item] {
			keys[item] = true
			result = append(result, item)
		}
	}

	return result
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
	serviceDomainsForCleanup := make(map[string][]string)
	allExcluded := make(map[string]struct{})
	var mu sync.Mutex


	var v2flyCategories []string
	for _, cfg := range config.Services {
		v2flyCategories = append(v2flyCategories, cfg.V2fly...)
	}

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

		originalName := name

		normalizedName := strings.ToLower(name)

		serviceGeneral[normalizedName] = getGeneralValue(cfg.General)
		name, cfg := originalName, cfg

		g.Go(func() error {
			domains, err := processDomainSources(ctx, cfg.URL, cfg.Domains, v2flyData, cfg.V2fly)
			if err != nil {
				logger.Warn("Error processing service %s: %v", name, err)
				domains = []string{}
			}


			servicePath := filepath.Join(categoriesDir, name, name+".lst")
			if err := saveDomains(servicePath, domains); err != nil {
				return fmt.Errorf("save service domains for %s: %w", name, err)
			}

			mu.Lock()

			serviceDomains[normalizedName] = domains

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

		normalizedServiceName := strings.ToLower(serviceName)
		if data, ok := serviceDomains[normalizedServiceName]; ok {

			if serviceExists := serviceGeneral[normalizedServiceName]; serviceExists {

				for _, d := range data {
					domainSet[d] = struct{}{}
				}
			} else {

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

		originalName := name
		name, cfg := originalName, cfg

		g.Go(func() error {
			domains, err := processGroup(ctx, name, cfg, v2flyData, serviceDomains, serviceGeneral)
			if err != nil {
				logger.Warn("Error processing group %s: %v", name, err)
				domains = []string{}
			}


			groupPath := filepath.Join(groupsDir, name, name+".lst")
			if err := saveDomains(groupPath, domains); err != nil {
				return fmt.Errorf("save group domains for %s: %w", name, err)
			}


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

	domainsToRemove := make(map[string]struct{})

	for serviceName, domains := range serviceDomainsForCleanup {
		if !serviceGeneral[serviceName] {
			for _, domain := range domains {
				domainsToRemove[domain] = struct{}{}
			}
		}
	}


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

	cleanedExistingDomains := cleanupDomainsFromMainFile(serviceDomainsForCleanup, serviceGeneral, existingDomains)

	mainDomains := make(map[string]struct{})


	for d := range cleanedExistingDomains {
		mainDomains[d] = struct{}{}
	}


	for name, domains := range serviceDomains {
		if serviceGeneral[name] {
			for _, d := range domains {
				mainDomains[d] = struct{}{}
			}
		}
	}


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


	serviceDomains, serviceGeneral, allExcluded, v2flyData, serviceDomainsForCleanup, err := processServices(ctx, config)
	if err != nil {
		logger.Error("Services processing error: %v", err)
		os.Exit(1)
	}


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
