package main

import (
	"bufio"
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
	"time"
)

const (
	MainDomainsFile    = "data/domains/domains-summary.lst"
	SourcesList        = "scripts/sources/domains.txt"
	OutputDir          = "data/compared-domains"
	YouTubeDomainsFile = "data/domains/services/YouTube/YouTube.lst"
	NonYouTubeOutput   = "data/domains/domains-summary-no-yt.lst"
	GroupsDir          = "data/domains/groups"
	ServicesDir        = "data/domains/services"
	TLDUrl             = "https://data.iana.org/TLD/tlds-alpha-by-domain.txt"
)
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
type DomainProcessor struct {
	re1           *regexp.Regexp
	re2           *regexp.Regexp
	re3           *regexp.Regexp
	re4           *regexp.Regexp
	re5           *regexp.Regexp
	re6           *regexp.Regexp
	domainPattern *regexp.Regexp
	tldSet        map[string]bool
}
func NewDomainProcessor(tldSet map[string]bool) *DomainProcessor {
	logger.Info("Creating new DomainProcessor")
	return &DomainProcessor{
		re1:           regexp.MustCompile(`^\s*-\s*`),
		re2:           regexp.MustCompile(`^\s*(#|;|//|--).*`),
		re3:           regexp.MustCompile(`^full:`),
		re4:           regexp.MustCompile(`^(https?://|//)`),
		re5:           regexp.MustCompile(`[/:].*$`),
		re6:           regexp.MustCompile(`^www[2-9]?\.`),
		domainPattern: regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`),
		tldSet:        tldSet,
	}
}
func (dp *DomainProcessor) CleanLine(line string) string {
	cleaned := strings.TrimSpace(line)
	cleaned = dp.re1.ReplaceAllString(cleaned, "")
	cleaned = dp.re2.ReplaceAllString(cleaned, "")
	cleaned = dp.re3.ReplaceAllString(cleaned, "")
	cleaned = dp.re4.ReplaceAllString(cleaned, "")
	cleaned = dp.re5.ReplaceAllString(cleaned, "")
	cleaned = dp.re6.ReplaceAllString(cleaned, "")
	return strings.TrimSpace(cleaned)
}
func (dp *DomainProcessor) CheckFileExists(path string) bool {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		logger.Error("File does not exist: %s", path)
		return false
	}
	return true
}
func (dp *DomainProcessor) ReadLines(filePath string) ([]string, error) {
	logger.Info("Reading lines from: %s", filePath)
	if !dp.CheckFileExists(filePath) {
		return nil, fmt.Errorf("file does not exist: %s", filePath)
	}

	file, err := os.Open(filePath)
	if err != nil {
		logger.Error("Error opening file %s: %v", filePath, err)
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	lineCount := 0

    for scanner.Scan() {
        cleaned := dp.CleanLine(scanner.Text())
        if cleaned == "" {
            continue
        }
        if dp.tldSet[strings.ToUpper(cleaned)] {
            lines = append(lines, cleaned)
            continue
        }
        if dp.domainPattern.MatchString(cleaned) {
            lines = append(lines, cleaned)
        } else {
            logger.Warn("Invalid domain format: %s", cleaned)
        }
    }

	if err := scanner.Err(); err != nil {
		logger.Error("Scanner error for %s: %v", filePath, err)
		return nil, err
	}

	logger.Info("Read %d valid lines from %s (total processed: %d)", len(lines), filePath, lineCount)
	return lines, nil
}
func (dp *DomainProcessor) WriteLines(filePath string, lines []string) error {
	logger.Info("Writing %d lines to: %s", len(lines), filePath)
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		logger.Error("Error creating directory %s: %v", dir, err)
		return err
	}

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
func (dp *DomainProcessor) FilterSubdomains(domains []string) []string {
	logger.Info("Filtering subdomains from %d domains", len(domains))

	if len(domains) == 0 {
		return domains
	}
	sort.Slice(domains, func(i, j int) bool {
		return strings.Count(domains[i], ".") < strings.Count(domains[j], ".")
	})

	keep := make(map[string]bool)
	var filtered []string

    for _, domain := range domains {
        upperDomain := strings.ToUpper(domain)
        if dp.tldSet[upperDomain] {
            if !keep[upperDomain] {
                filtered = append(filtered, domain)
                keep[domain] = true
            }
            continue
        }

		parts := strings.Split(domain, ".")
		if len(parts) < 2 && !dp.tldSet[strings.ToUpper(domain)] {
			continue
		}

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
func (dp *DomainProcessor) CompareFiles(list1, list2 []string) (only1, only2, common []string) {
	logger.Info("Comparing %d vs %d domains", len(list1), len(list2))
	set1 := make(map[string]bool)
	set2 := make(map[string]bool)

	for _, domain := range list1 {
		set1[domain] = true
	}

	for _, domain := range list2 {
		set2[domain] = true
	}
	for domain := range set1 {
		if set2[domain] {
			common = append(common, domain)
		} else {
			only1 = append(only1, domain)
		}
	}

	for domain := range set2 {
		if !set1[domain] {
			only2 = append(only2, domain)
		}
	}
	sort.Strings(only1)
	sort.Strings(only2)
	sort.Strings(common)

	logger.Info("Comparison results: only1=%d, only2=%d, common=%d",
		len(only1), len(only2), len(common))
	return
}
func (dp *DomainProcessor) ProcessLstFiles(baseDir string) error {
	logger.Info("Processing .lst files in directory: %s", baseDir)
	if _, err := os.Stat(baseDir); os.IsNotExist(err) {
		logger.Warn("Directory does not exist: %s", baseDir)
		return nil
	}

	var processedFiles int
	var mu sync.Mutex
	var wg sync.WaitGroup

	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			logger.Error("Error walking path %s: %v", path, err)
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".lst") {
			wg.Add(1)
			go func(filePath string) {
				defer wg.Done()
				domains, err := dp.ReadLines(filePath)
				if err != nil {
					logger.Error("Error reading domains from %s: %v", filePath, err)
					return
				}

				if len(domains) == 0 {
					logger.Info("No domains found in %s, skipping", filePath)
					return
				}
				filtered := dp.FilterSubdomains(domains)
				if err := dp.WriteLines(filePath, filtered); err != nil {
					logger.Error("Error writing filtered domains to %s: %v", filePath, err)
					return
				}

				mu.Lock()
				processedFiles++
				mu.Unlock()

				logger.Info("Successfully processed %s: %d -> %d domains",
					filePath, len(domains), len(filtered))
			}(path)
		}

		return nil
	})

	wg.Wait()

	if err != nil {
		logger.Error("Error walking directory %s: %v", baseDir, err)
		return err
	}

	logger.Info("Completed processing %d .lst files in %s", processedFiles, baseDir)
	return nil
}
type DomainComparator struct {
	*DomainProcessor
	sourcesPath    string
	outputDir      string
	primaryDomains map[string]bool
	client         *http.Client
}
func NewDomainComparator(sourcesPath, outputDir string, tldSet map[string]bool) *DomainComparator {
	logger.Info("Creating DomainComparator with sources: %s, output: %s",
		sourcesPath, outputDir)

	return &DomainComparator{
		DomainProcessor: NewDomainProcessor(tldSet),
		sourcesPath:     sourcesPath,
		outputDir:       outputDir,
		primaryDomains:  make(map[string]bool),
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}
func (dc *DomainComparator) ProcessExternalSource(url string) []string {
	logger.Info("Processing external source: %s", url)

	resp, err := dc.client.Get(url)
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
	commentPattern := regexp.MustCompile(`(?m)^\s*[#;].*$`)
	emptyPattern := regexp.MustCompile(`(?m)^\s*$`)
	hostsPattern := regexp.MustCompile(`(?m)^[0-9.]+\s+(.+)$`)

	content := string(body)
	if strings.Contains(content, "127.0.0.1") || strings.Contains(content, "0.0.0.0") {
		matches := hostsPattern.FindAllStringSubmatch(content, -1)
		var hostsDomains []string
		for _, match := range matches {
			if len(match) > 1 {
				domain := strings.TrimSpace(match[1])
				if domain != "" {
					hostsDomains = append(hostsDomains, domain)
				}
			}
		}
		if len(hostsDomains) > 0 {
			return dc.processDomains(hostsDomains)
		}
	}
	content = commentPattern.ReplaceAllString(content, "")
	content = emptyPattern.ReplaceAllString(content, "")

	var domains []string
	scanner := bufio.NewScanner(strings.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		cleaned := dc.CleanLine(line)
		if cleaned == "" {
			continue
		}
		upperCleaned := strings.ToUpper(cleaned)
		if dc.tldSet[upperCleaned] {
			domains = append(domains, cleaned)
			continue
		}
		if dc.domainPattern.MatchString(cleaned) {
			domains = append(domains, cleaned)
		}
	}

	return dc.processDomains(domains)
}
func (dc *DomainComparator) processDomains(domains []string) []string {
	var filtered []string
	for _, domain := range domains {
		parts := strings.Split(domain, ".")
		skip := false
		for i := 1; i < len(parts); i++ {
			parent := strings.Join(parts[i:], ".")
			if dc.primaryDomains[parent] {
				skip = true
				break
			}
		}

		if !skip {
			filtered = append(filtered, domain)
		}
	}
	seen := make(map[string]struct{})
	var unique []string
	for _, d := range filtered {
		if _, exists := seen[d]; !exists {
			seen[d] = struct{}{}
			unique = append(unique, d)
		}
	}

	sort.Strings(unique)
	logger.Info("Processed %d unique domains", len(unique))
	return unique
}
func (dc *DomainComparator) GenerateReports(sourceURL string, externalDomains, primarySorted []string) error {
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
		if err := os.MkdirAll(dc.outputDir, 0755); err != nil {
			logger.Error("Error creating output directory: %v", err)
			continue
		}

		f, err := os.OpenFile(reportFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			logger.Error("Error opening report file %s: %v", reportFile, err)
			continue
		}

		_, err = f.WriteString(fmt.Sprintf("# %s domains\n", strings.Title(reportType)))
		if err != nil {
			logger.Error("Error writing header to %s: %v", reportFile, err)
			f.Close()
			continue
		}

		_, err = f.WriteString(fmt.Sprintf("# Source: %s\n\n", sourceURL))
		if err != nil {
			logger.Error("Error writing source to %s: %v", reportFile, err)
			f.Close()
			continue
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

		f.Close()

		logger.Info("Generated %s report for %s with %d domains",
			reportType, sourceURL, len(data))
	}

	return nil
}
func (dc *DomainComparator) ProcessSources(primaryDomains []string) error {
	logger.Info("Processing sources with %d primary domains", len(primaryDomains))
	if !dc.CheckFileExists(dc.sourcesPath) {
		logger.Warn("Sources file does not exist: %s", dc.sourcesPath)
		return nil
	}
	missingFile := filepath.Join(dc.outputDir, "missing-domains.txt")
	presenceFile := filepath.Join(dc.outputDir, "presence-domains.txt")

	if err := os.Remove(missingFile); err != nil && !os.IsNotExist(err) {
		logger.Warn("Error removing missing-domains.txt: %v", err)
	}
	if err := os.Remove(presenceFile); err != nil && !os.IsNotExist(err) {
		logger.Warn("Error removing presence-domains.txt: %v", err)
	}
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
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			sourceURLs = append(sourceURLs, line)
		}
	}

	if err := scanner.Err(); err != nil {
		logger.Error("Error reading sources list: %v", err)
		return err
	}

	logger.Info("Found %d sources to process", len(sourceURLs))
	for _, domain := range primaryDomains {
		dc.primaryDomains[domain] = true
	}
	primarySorted := make([]string, len(primaryDomains))
	copy(primarySorted, primaryDomains)
	sort.Strings(primarySorted)
	for _, url := range sourceURLs {
		logger.Info("Processing source: %s", url)
		externalDomains := dc.ProcessExternalSource(url)
		if len(externalDomains) > 0 {
			if err := dc.GenerateReports(url, externalDomains, primarySorted); err != nil {
				logger.Error("Error generating reports for %s: %v", url, err)
			}
		} else {
			logger.Warn("No domains processed for source: %s", url)
		}
	}

	logger.Info("Finished processing %d sources", len(sourceURLs))
	return nil
}
func loadTLDSet() (map[string]bool, error) {
	logger.Info("Loading TLD set from %s", TLDUrl)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(TLDUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to download TLD list: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to download TLD list: status %s", resp.Status)
	}

	tldSet := make(map[string]bool)
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		tldSet[strings.ToUpper(line)] = true
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading TLD list: %v", err)
	}

	logger.Info("Loaded %d TLDs", len(tldSet))
	return tldSet, nil
}

func main() {
	logger.Info("Starting domain processing")
	tldSet, err := loadTLDSet()
	if err != nil {
		logger.Error("Error loading TLD set: %v", err)
	} else {
		logger.Info("Successfully loaded TLD set")
	}
	pwd, _ := os.Getwd()
	logger.Info("Working directory: %s", pwd)

	dp := NewDomainProcessor(tldSet)
	logger.Info("Processing main domains file: %s", MainDomainsFile)
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

    if err := dp.ProcessLstFiles(GroupsDir); err != nil {
        logger.Error("Error processing groups directory: %v", err)
    }
    
    if err := dp.ProcessLstFiles(ServicesDir); err != nil {
        logger.Error("Error processing services directory: %v", err)
    }
	logger.Info("Processing groups directory: %s", GroupsDir)
	if err := dp.ProcessLstFiles(GroupsDir); err != nil {
		logger.Error("Error processing groups directory: %v", err)
	}
	logger.Info("Processing services directory: %s", ServicesDir)
	if err := dp.ProcessLstFiles(ServicesDir); err != nil {
		logger.Error("Error processing services directory: %v", err)
	}
	logger.Info("Creating output directory: %s", OutputDir)
	if err := os.MkdirAll(OutputDir, 0755); err != nil {
		logger.Error("Fatal error creating output dir: %v", err)
		os.Exit(1)
	}
	logger.Info("Starting comparison with external sources")
    comparator := NewDomainComparator(SourcesList, OutputDir, tldSet)
    if err := comparator.ProcessSources(filteredDomains); err != nil {
        logger.Error("Error processing sources: %v", err)
    }
	logger.Info("Filtering YouTube domains")
	ytDomains, err := dp.ReadLines(YouTubeDomainsFile)
	if err != nil {
		logger.Warn("Error reading YouTube domains (continuing without filtering): %v", err)
		ytDomains = []string{}
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
		logger.Error("Error writing non-YouTube domains: %v", err)
	}

	logger.Info("Domain processing completed successfully")
	logger.Info("Total domains processed: %d", len(filteredDomains))
	logger.Info("Non-YouTube domains: %d", len(nonYT))
}
