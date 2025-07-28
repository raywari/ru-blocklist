package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/pelletier/go-toml/v2"
	"github.com/thcyron/cidrmerge"
	"golang.org/x/sync/errgroup"
)

const (
	CONFIG_FILE          = "scripts/config/process-subnets.toml"
	MAX_RETRIES          = 3
	RETRY_DELAY          = 2 * time.Second
	BACKOFF_FACTOR       = 2
	BASE_CATEGORIES_DIR  = "data"
	CIDRS_DIR            = "CIDRs"
	CIDR4_DIR            = "CIDR4"
	CIDR6_DIR            = "CIDR6"
	SERVICES_DIR         = "services"
	SUMMARY_CIDR4_FILE   = "CIDR4-summary.lst"
	SUMMARY_CIDR6_FILE   = "CIDR6-summary.lst"
	SUMMARY_CIDRS_FILE   = "CIDRs-summary.lst"
)

func getCIDRsBasePath() string {
	return filepath.Join(BASE_CATEGORIES_DIR, CIDRS_DIR)
}

func getCIDR4BasePath() string {
	return filepath.Join(BASE_CATEGORIES_DIR, CIDRS_DIR, CIDR4_DIR)
}

func getCIDR6BasePath() string {
	return filepath.Join(BASE_CATEGORIES_DIR, CIDRS_DIR, CIDR6_DIR)
}

func getCIDR4ServicesPath() string {
	return filepath.Join(getCIDR4BasePath(), SERVICES_DIR)
}

func getCIDR6ServicesPath() string {
	return filepath.Join(getCIDR6BasePath(), SERVICES_DIR)
}

func getServiceCIDR4Path(serviceName string) string {
	return filepath.Join(getCIDR4ServicesPath(), serviceName)
}

func getServiceCIDR6Path(serviceName string) string {
	return filepath.Join(getCIDR6ServicesPath(), serviceName)
}

func getServiceCIDR4File(serviceName string) string {
	return filepath.Join(getServiceCIDR4Path(serviceName), strings.ToLower(serviceName)+".lst")
}

func getServiceCIDR6File(serviceName string) string {
	return filepath.Join(getServiceCIDR6Path(serviceName), strings.ToLower(serviceName)+".lst")
}

func getSummaryCIDR4File() string {
	return filepath.Join(getCIDR4BasePath(), SUMMARY_CIDR4_FILE)
}

func getSummaryCIDR6File() string {
	return filepath.Join(getCIDR6BasePath(), SUMMARY_CIDR6_FILE)
}

func getSummaryCIDRsFile() string {
	return filepath.Join(getCIDRsBasePath(), SUMMARY_CIDRS_FILE)
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

type Config struct {
	Services map[string]ServiceConfig `toml:"services"`
	Settings SettingsConfig           `toml:"settings"`
}

type ServiceConfig struct {
	Type  string   `toml:"type"`
	V4URL []string `toml:"v4_url,omitempty"`
	V6URL []string `toml:"v6_url,omitempty"`
	URL   []string `toml:"url,omitempty"`
	ASN   any      `toml:"asn,omitempty"`
}

type SettingsConfig struct {
	Summary   []string `toml:"summary"`
	UserAgent string   `toml:"user_agent"`
	BGPURL    string   `toml:"bgp_url"`
}

type NetworkCollector struct {
	v4Networks []*net.IPNet
	v6Networks []*net.IPNet
	mu         sync.RWMutex
}

func NewNetworkCollector() *NetworkCollector {
	return &NetworkCollector{
		v4Networks: make([]*net.IPNet, 0, 1000),
		v6Networks: make([]*net.IPNet, 0, 1000),
	}
}

func (nc *NetworkCollector) AddNetwork(networkStr string) {
	networkStr = strings.TrimSpace(networkStr)
	if networkStr == "" {
		return
	}

	// Попытка разобрать как CIDR
	_, network, err := net.ParseCIDR(networkStr)
	if err != nil {
		// Если не CIDR, проверим на одиночный IP
		ip := net.ParseIP(networkStr)
		if ip == nil {
			logger.Warn("Invalid network skipped: %s - %v", networkStr, err)
			return
		}

		// Автоматически добавляем маску для одиночных IP
		if ip.To4() != nil {
			networkStr += "/32"
		} else {
			networkStr += "/128"
		}

		// Повторная попытка разбора после добавления маски
		_, network, err = net.ParseCIDR(networkStr)
		if err != nil {
			logger.Warn("Invalid network skipped after conversion: %s - %v", networkStr, err)
			return
		}
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()
	if network.IP.To4() != nil {
		nc.v4Networks = append(nc.v4Networks, network)
	} else {
		nc.v6Networks = append(nc.v6Networks, network)
	}
}

// Удаляет подсети, полностью входящие в другие сети
func removeSubnets(networks []*net.IPNet) []*net.IPNet {
	if len(networks) == 0 {
		return networks
	}

	// Сортируем по длине маски (от меньшей к большей)
	sort.Slice(networks, func(i, j int) bool {
		iOnes, _ := networks[i].Mask.Size()
		jOnes, _ := networks[j].Mask.Size()
		return iOnes < jOnes
	})

	result := []*net.IPNet{}
	for _, net := range networks {
		contained := false
		for _, existing := range result {
			if existing.Contains(net.IP) {
				existingOnes, _ := existing.Mask.Size()
				netOnes, _ := net.Mask.Size()
				if existingOnes <= netOnes {
					contained = true
					break
				}
			}
		}
		if !contained {
			result = append(result, net)
		}
	}
	return result
}

func (nc *NetworkCollector) GetMergedNetworks() ([]string, []string) {
	nc.mu.RLock()
	defer nc.mu.RUnlock()
	
	// Объединяем смежные подсети
	mergedV4 := cidrmerge.Merge(nc.v4Networks)
	mergedV6 := cidrmerge.Merge(nc.v6Networks)
	
	// Удаляем подсети, полностью входящие в другие сети
	mergedV4 = removeSubnets(mergedV4)
	mergedV6 = removeSubnets(mergedV6)

	v4Strings := make([]string, len(mergedV4))
	v6Strings := make([]string, len(mergedV6))
	for i, net := range mergedV4 {
		v4Strings[i] = net.String()
	}
	for i, net := range mergedV6 {
		v6Strings[i] = net.String()
	}
	return v4Strings, v6Strings
}

type HTTPClient struct {
	client    *http.Client
	userAgent string
}

func NewHTTPClient(userAgent string) *HTTPClient {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return &HTTPClient{
		userAgent: userAgent,
		client: &http.Client{
			Timeout: 10 * time.Minute, // Увеличиваем общий таймаут до 10 минут
			Transport: &http.Transport{
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
				DisableKeepAlives:     false,
				ResponseHeaderTimeout: 60 * time.Second, // Увеличиваем таймаут заголовков
				ExpectContinueTimeout: 1 * time.Second,
				DialContext:           dialer.DialContext,
			},
		},
	}
}

func (c *HTTPClient) Download(ctx context.Context, url string) (string, error) {
	return c.DownloadWithRetry(ctx, url, MAX_RETRIES)
}

func (c *HTTPClient) DownloadWithRetry(ctx context.Context, url string, maxRetries int) (string, error) {
	var lastErr error
	delay := RETRY_DELAY

	for attempt := 0; attempt <= maxRetries; attempt++ {
		if attempt > 0 {
			logger.Warn("Retrying download attempt %d/%d for %s after %v", attempt, maxRetries, url, delay)
			select {
			case <-time.After(delay):
			case <-ctx.Done():
				return "", ctx.Err()
			}
			delay *= BACKOFF_FACTOR
		}
		
		// Создаем контекст с увеличенным таймаутом для больших файлов
		reqCtx := ctx
		if strings.Contains(url, "table.txt") || strings.Contains(url, "bgp") {
			// Для BGP файлов используем контекст без таймаута или с очень большим таймаутом
			reqCtx = context.Background()
		}
		
		req, err := http.NewRequestWithContext(reqCtx, "GET", url, nil)
		if err != nil {
			lastErr = err
			continue
		}
		if c.userAgent != "" {
			req.Header.Set("User-Agent", c.userAgent)
		}
		
		logger.Info("Starting download attempt %d for %s", attempt+1, url)
		start := time.Now()
		
		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			logger.Warn("Download attempt %d failed for %s after %v: %v", attempt+1, url, time.Since(start), err)
			continue
		}
		
		if resp.StatusCode == http.StatusTooManyRequests {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			retryAfter := resp.Header.Get("Retry-After")
			if retryAfter != "" {
				if seconds, err := strconv.Atoi(retryAfter); err == nil {
					delay = time.Duration(seconds) * time.Second
				} else if t, err := time.Parse(time.RFC1123, retryAfter); err == nil {
					delay = time.Until(t)
				}
			}
			logger.Warn("HTTP 429. Retrying after %v", delay)
			continue
		}
		
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			logger.Warn("Download attempt %d failed for %s after %v: %v", attempt+1, url, time.Since(start), lastErr)
			continue
		}
		
		// Получаем размер файла если доступен
		contentLength := resp.Header.Get("Content-Length")
		if contentLength != "" {
			if size, err := strconv.ParseInt(contentLength, 10, 64); err == nil {
				logger.Info("Downloading %s (%.2f MB)", url, float64(size)/(1024*1024))
			}
		}
		
		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		
		downloadTime := time.Since(start)
		
		if err != nil {
			lastErr = err
			logger.Warn("Download attempt %d failed for %s after %v: %v", attempt+1, url, downloadTime, err)
			continue
		}
		
		if attempt > 0 {
			logger.Info("Successfully downloaded %s after %d attempts in %v (%.2f MB)", 
				url, attempt+1, downloadTime, float64(len(data))/(1024*1024))
		} else {
			logger.Info("Successfully downloaded %s in %v (%.2f MB)", 
				url, downloadTime, float64(len(data))/(1024*1024))
		}
		
		return string(data), nil
	}
	logger.Error("Failed to download %s after %d attempts: %v", url, maxRetries+1, lastErr)
	return "", fmt.Errorf("failed after %d attempts: %w", maxRetries+1, lastErr)
}

func setupDirectories(services map[string]ServiceConfig) error {
	for name := range services {
		dirs := []string{
			getServiceCIDR4Path(name),
			getServiceCIDR6Path(name),
		}

		for _, dir := range dirs {
			if err := os.MkdirAll(dir, 0755); err != nil {
				return fmt.Errorf("failed to create directory %s: %w", dir, err)
			}
		}
	}
	return nil
}

func writeNetworksToFile(filename string, networks []string) error {
	if len(networks) == 0 {
		return nil
	}

	// Сортируем сети перед записью
	sort.Strings(networks)

	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	defer writer.Flush()

	for _, network := range networks {
		if _, err := writer.WriteString(network + "\n"); err != nil {
			return err
		}
	}
	return nil
}

func sortAllFiles(services map[string]ServiceConfig) error {
	logger.Info("Sorting all service files...")
	
	for name := range services {
		// Сортировка IPv4 файлов
		v4File := getServiceCIDR4File(name)
		if err := sortFile(v4File); err != nil {
			logger.Warn("Failed to sort IPv4 file for %s: %v", name, err)
		}
		
		// Сортировка IPv6 файлов
		v6File := getServiceCIDR6File(name)
		if err := sortFile(v6File); err != nil {
			logger.Warn("Failed to sort IPv6 file for %s: %v", name, err)
		}
	}
	
	// Сортировка summary файлов
	summaryFiles := []string{
		getSummaryCIDR4File(),
		getSummaryCIDR6File(),
		getSummaryCIDRsFile(),
	}
	
	for _, file := range summaryFiles {
		if err := sortFile(file); err != nil {
			logger.Warn("Failed to sort summary file %s: %v", file, err)
		}
	}
	
	logger.Info("File sorting completed")
	return nil
}

func sortFile(filename string) error {
	// Проверяем существование файла
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil // Файл не существует, пропускаем
	}
	
	// Читаем файл
	data, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	
	if len(data) == 0 {
		return nil // Пустой файл
	}
	
	// Разбиваем на строки
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) == 0 {
		return nil
	}
	
	// Удаляем пустые строки и сортируем
	validLines := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			validLines = append(validLines, line)
		}
	}
	
	if len(validLines) == 0 {
		return nil
	}
	
	sort.Strings(validLines)
	
	// Записываем обратно в файл
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	
	for _, line := range validLines {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	
	return nil
}

func processURLService(ctx context.Context, client *HTTPClient, name string, config ServiceConfig) error {
	logger.Info("Processing URL service: %s", name)

	g, ctx := errgroup.WithContext(ctx)
	var v4Networks, v6Networks []string

	// Обработка IPv4 URLs
	g.Go(func() error {
		if len(config.V4URL) == 0 {
			return nil
		}
		collector := NewNetworkCollector()
		for _, url := range config.V4URL {
			data, err := client.Download(ctx, url)
			if err != nil {
				logger.Error("Failed to download IPv4 data from %s: %v", url, err)
				continue
			}
			scanner := bufio.NewScanner(strings.NewReader(data))
			for scanner.Scan() {
				collector.AddNetwork(scanner.Text())
			}
		}
		v4Networks, _ = collector.GetMergedNetworks()
		return nil
	})

	// Обработка IPv6 URLs
	g.Go(func() error {
		if len(config.V6URL) == 0 {
			return nil
		}
		collector := NewNetworkCollector()
		for _, url := range config.V6URL {
			data, err := client.Download(ctx, url)
			if err != nil {
				logger.Error("Failed to download IPv6 data from %s: %v", url, err)
				continue
			}
			scanner := bufio.NewScanner(strings.NewReader(data))
			for scanner.Scan() {
				collector.AddNetwork(scanner.Text())
			}
		}
		_, v6Networks = collector.GetMergedNetworks()
		return nil
	})

	if err := g.Wait(); err != nil {
		return err
	}

	v4File := getServiceCIDR4File(name)
	v6File := getServiceCIDR6File(name)
	if err := writeNetworksToFile(v4File, v4Networks); err != nil {
		logger.Error("Failed to write IPv4 file for %s: %v", name, err)
	}
	if err := writeNetworksToFile(v6File, v6Networks); err != nil {
		logger.Error("Failed to write IPv6 file for %s: %v", name, err)
	}
	logger.Info("Completed URL service: %s (IPv4: %d, IPv6: %d)", name, len(v4Networks), len(v6Networks))
	return nil
}

func processSingleURLService(ctx context.Context, client *HTTPClient, name string, config ServiceConfig) error {
	logger.Info("Processing single URL service: %s", name)

	collector := NewNetworkCollector()
	for _, url := range config.URL {
		data, err := client.Download(ctx, url)
		if err != nil {
			logger.Error("Failed to download data from %s: %v", url, err)
			continue
		}
		scanner := bufio.NewScanner(strings.NewReader(data))
		for scanner.Scan() {
			collector.AddNetwork(scanner.Text())
		}
	}

	v4Networks, v6Networks := collector.GetMergedNetworks()
	v4File := getServiceCIDR4File(name)
	v6File := getServiceCIDR6File(name)
	if err := writeNetworksToFile(v4File, v4Networks); err != nil {
		logger.Error("Failed to write IPv4 file for %s: %v", name, err)
	}
	if err := writeNetworksToFile(v6File, v6Networks); err != nil {
		logger.Error("Failed to write IPv6 file for %s: %v", name, err)
	}
	logger.Info("Completed single URL service: %s (IPv4: %d, IPv6: %d)", name, len(v4Networks), len(v6Networks))
	return nil
}

func parseASNs(asnData any) ([]int, error) {
	switch v := asnData.(type) {
	case int64:
		return []int{int(v)}, nil
	case []any:
		asns := make([]int, 0, len(v))
		for _, item := range v {
			if asn, ok := item.(int64); ok {
				asns = append(asns, int(asn))
			} else {
				return nil, fmt.Errorf("invalid ASN type: %T", item)
			}
		}
		return asns, nil
	default:
		return nil, fmt.Errorf("unsupported ASN data type: %T", v)
	}
}

func processASNServices(ctx context.Context, client *HTTPClient, services map[string]ServiceConfig, bgpURL string) error {
	logger.Info("Processing ASN services...")
	asnServices := make(map[string][]int)
	for name, config := range services {
		if config.Type == "asn" && config.ASN != nil {
			asns, err := parseASNs(config.ASN)
			if err != nil {
				logger.Error("Failed to parse ASNs for %s: %v", name, err)
				continue
			}
			asnServices[name] = asns
		}
	}

	if len(asnServices) == 0 {
		logger.Info("No ASN services found")
		return nil
	}

	allASNs := make(map[int][]string)
	for service, asns := range asnServices {
		for _, asn := range asns {
			allASNs[asn] = append(allASNs[asn], service)
		}
	}

	logger.Info("Downloading BGP data from: %s", bgpURL)
	// Для BGP файлов используем больше попыток и создаем отдельный контекст
	bgpCtx := context.Background() // Убираем ограничения по времени для BGP файла
	bgpData, err := client.DownloadWithRetry(bgpCtx, bgpURL, 5) // Больше попыток для BGP
	if err != nil {
		logger.Error("Failed to download BGP data from %s: %v", bgpURL, err)
		return fmt.Errorf("failed to download BGP data: %w", err)
	}

	if len(bgpData) == 0 {
		logger.Error("Downloaded BGP data is empty")
		return fmt.Errorf("BGP data is empty")
	}

	logger.Info("Successfully downloaded BGP data (%.2f MB)", float64(len(bgpData))/(1024*1024))

	serviceCollectors := make(map[string]*NetworkCollector)
	for service := range asnServices {
		serviceCollectors[service] = NewNetworkCollector()
	}

	scanner := bufio.NewScanner(strings.NewReader(bgpData))
	// Увеличиваем буфер для больших строк
	buf := make([]byte, 0, 64*1024)
	scanner.Buffer(buf, 1024*1024)
	
	lineCount := 0
	processedCount := 0
	
	for scanner.Scan() {
		lineCount++
		if lineCount%100000 == 0 {
			logger.Info("Processed %d BGP lines, found %d matching entries", lineCount, processedCount)
		}
		
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		
		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}
		
		cidr := parts[0]
		asnStr := parts[len(parts)-1]
		
		// Удаляем префикс AS если есть
		asnStr = strings.TrimPrefix(asnStr, "AS")
		
		asn, err := strconv.Atoi(asnStr)
		if err != nil {
			continue
		}

		if services, exists := allASNs[asn]; exists {
			processedCount++
			for _, service := range services {
				serviceCollectors[service].AddNetwork(cidr)
			}
		}
	}
	
	if err := scanner.Err(); err != nil {
		logger.Error("Error reading BGP data: %v", err)
		return fmt.Errorf("error reading BGP data: %w", err)
	}
	
	logger.Info("Processed %d BGP lines total, found %d matching entries", lineCount, processedCount)

	for service, collector := range serviceCollectors {
		v4Networks, v6Networks := collector.GetMergedNetworks()
		v4File := getServiceCIDR4File(service)
		v6File := getServiceCIDR6File(service)
		if err := writeNetworksToFile(v4File, v4Networks); err != nil {
			logger.Error("Failed to write IPv4 file for %s: %v", service, err)
		}
		if err := writeNetworksToFile(v6File, v6Networks); err != nil {
			logger.Error("Failed to write IPv6 file for %s: %v", service, err)
		}
		logger.Info("Completed ASN service: %s (IPv4: %d, IPv6: %d)", service, len(v4Networks), len(v6Networks))
	}
	return nil
}

func makeSummary(summary []string) error {
	logger.Info("Creating summary files...")

	allV4Collector := NewNetworkCollector()
	allV6Collector := NewNetworkCollector()

	for _, service := range summary {
		v4File := getServiceCIDR4File(service)
		if data, err := os.ReadFile(v4File); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				allV4Collector.AddNetwork(scanner.Text())
			}
		} else {
			logger.Warn("Could not read IPv4 file for service %s: %v", service, err)
		}

		v6File := getServiceCIDR6File(service)
		if data, err := os.ReadFile(v6File); err == nil {
			scanner := bufio.NewScanner(strings.NewReader(string(data)))
			for scanner.Scan() {
				allV6Collector.AddNetwork(scanner.Text())
			}
		} else {
			logger.Warn("Could not read IPv6 file for service %s: %v", service, err)
		}
	}

	mergedV4, _ := allV4Collector.GetMergedNetworks()
	_, mergedV6 := allV6Collector.GetMergedNetworks()

	if err := os.MkdirAll(getCIDR4BasePath(), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(getCIDR6BasePath(), 0755); err != nil {
		return err
	}
	if err := os.MkdirAll(getCIDRsBasePath(), 0755); err != nil {
		return err
	}

	if err := writeNetworksToFile(getSummaryCIDR4File(), mergedV4); err != nil {
		return err
	}
	if err := writeNetworksToFile(getSummaryCIDR6File(), mergedV6); err != nil {
		return err
	}

	combined := make([]string, 0, len(mergedV4)+len(mergedV6))
	combined = append(combined, mergedV4...)
	combined = append(combined, mergedV6...)
	sort.Strings(combined)
	if err := writeNetworksToFile(getSummaryCIDRsFile(), combined); err != nil {
		return err
	}

	logger.Info("Summary created (IPv4: %d, IPv6: %d, Total: %d)", len(mergedV4), len(mergedV6), len(combined))
	return nil
}

func main() {
	start := time.Now()
	logger.Info("Starting subnet processing...")

	configData, err := os.ReadFile(CONFIG_FILE)
	if err != nil {
		logger.Error("Failed to read config file: %v", err)
		os.Exit(1)
	}

	var config Config
	if err := toml.Unmarshal(configData, &config); err != nil {
		logger.Error("Failed to parse config: %v", err)
		os.Exit(1)
	}

	if err := setupDirectories(config.Services); err != nil {
		logger.Error("Failed to setup directories: %v", err)
		os.Exit(1)
	}

	ctx := context.Background()
	client := NewHTTPClient(config.Settings.UserAgent)

	g, ctx := errgroup.WithContext(ctx)

	// Обработка сервисов
	for name, serviceConfig := range config.Services {
		name := name
		serviceConfig := serviceConfig
		switch serviceConfig.Type {
		case "url":
			g.Go(func() error {
				return processURLService(ctx, client, name, serviceConfig)
			})
		case "single_url":
			g.Go(func() error {
				return processSingleURLService(ctx, client, name, serviceConfig)
			})
		case "asn":
			// ASN обрабатываются отдельно позже
		default:
			logger.Warn("Unknown service type '%s' for %s", serviceConfig.Type, name)
		}
	}

	if err := g.Wait(); err != nil {
		logger.Error("Error processing services: %v", err)
	}

	// Обработка ASN сервисов
	if config.Settings.BGPURL != "" {
		if err := processASNServices(ctx, client, config.Services, config.Settings.BGPURL); err != nil {
			logger.Error("Error processing ASN services: %v", err)
		}
	} else {
		logger.Warn("Skipping ASN services: no bgp_url provided")
	}

	// Создание summary
	if len(config.Settings.Summary) > 0 {
		if err := makeSummary(config.Settings.Summary); err != nil {
			logger.Error("Failed to create summary: %v", err)
		}
	} else {
		logger.Info("No summary services configured")
	}

	// Сортировка всех файлов в конце
	if err := sortAllFiles(config.Services); err != nil {
		logger.Error("Failed to sort files: %v", err)
	}

	logger.Info("Processing completed in %v", time.Since(start))
}