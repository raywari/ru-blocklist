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
	CONFIG_FILE    = "scripts/config/process-subnets.toml"
	MAX_RETRIES    = 3
	RETRY_DELAY    = 2 * time.Second
	BACKOFF_FACTOR = 2
	
	// Path constants
	BASE_CATEGORIES_DIR = "data"
	CIDRS_DIR          = "CIDRs"
	CIDR4_DIR          = "CIDR4"
	CIDR6_DIR          = "CIDR6"
	SERVICES_DIR       = "services"
	
	// File names
	SUMMARY_CIDR4_FILE = "CIDR4-summary.lst"
	SUMMARY_CIDR6_FILE = "CIDR6-summary.lst"
	SUMMARY_CIDRS_FILE = "CIDRs-summary.lst"
)

// Path helper functions
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
	Type   string `toml:"type"`
	V4URL  string `toml:"v4_url,omitempty"`
	V6URL  string `toml:"v6_url,omitempty"`
	URL    string `toml:"url,omitempty"`
	ASN    any    `toml:"asn,omitempty"`
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

	_, network, err := net.ParseCIDR(networkStr)
	if err != nil {
		logger.Warn("Invalid network skipped: %s - %v", networkStr, err)
		return
	}

	nc.mu.Lock()
	defer nc.mu.Unlock()

	if network.IP.To4() != nil {
		nc.v4Networks = append(nc.v4Networks, network)
	} else {
		nc.v6Networks = append(nc.v6Networks, network)
	}
}

func (nc *NetworkCollector) GetMergedNetworks() ([]string, []string) {
	nc.mu.RLock()
	defer nc.mu.RUnlock()

	// Используем библиотеку cidrmerge для эффективного объединения сетей
	mergedV4 := cidrmerge.Merge(nc.v4Networks)
	mergedV6 := cidrmerge.Merge(nc.v6Networks)

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
	// Создаем кастомный диалер с таймаутом
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	return &HTTPClient{
		userAgent: userAgent,
		client: &http.Client{
			Timeout: 60 * time.Second, // Увеличиваем таймаут для больших файлов
			Transport: &http.Transport{
				MaxIdleConns:          100,
				MaxIdleConnsPerHost:   10,
				IdleConnTimeout:       90 * time.Second,
				DisableKeepAlives:     false,
				ResponseHeaderTimeout: 30 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				// Используем кастомный диалер
				DialContext: dialer.DialContext,
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

		req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
		if err != nil {
			lastErr = err
			continue
		}

		// Устанавливаем User-Agent
		if c.userAgent != "" {
			req.Header.Set("User-Agent", c.userAgent)
		}

		resp, err := c.client.Do(req)
		if err != nil {
			lastErr = err
			logger.Warn("Download attempt %d failed for %s: %v", attempt+1, url, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			logger.Warn("Download attempt %d failed for %s: %v", attempt+1, url, lastErr)
			continue
		}

		data, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			logger.Warn("Download attempt %d failed for %s: %v", attempt+1, url, err)
			continue
		}

		if attempt > 0 {
			logger.Info("Successfully downloaded %s after %d attempts", url, attempt+1)
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

func processURLService(ctx context.Context, client *HTTPClient, name string, config ServiceConfig) error {
	logger.Info("Processing URL service: %s", name)

	g, ctx := errgroup.WithContext(ctx)
	var v4Networks, v6Networks []string

	// Загружаем IPv4 сети
	g.Go(func() error {
		if config.V4URL == "" {
			return nil
		}
		data, err := client.Download(ctx, config.V4URL)
		if err != nil {
			logger.Error("Failed to download IPv4 data for %s: %v", name, err)
			return nil // Не прерываем выполнение из-за ошибки загрузки
		}

		collector := NewNetworkCollector()
		scanner := bufio.NewScanner(strings.NewReader(data))
		for scanner.Scan() {
			collector.AddNetwork(scanner.Text())
		}

		v4Networks, _ = collector.GetMergedNetworks()
		return nil
	})

	// Загружаем IPv6 сети
	g.Go(func() error {
		if config.V6URL == "" {
			return nil
		}
		data, err := client.Download(ctx, config.V6URL)
		if err != nil {
			logger.Error("Failed to download IPv6 data for %s: %v", name, err)
			return nil
		}

		collector := NewNetworkCollector()
		scanner := bufio.NewScanner(strings.NewReader(data))
		for scanner.Scan() {
			collector.AddNetwork(scanner.Text())
		}

		_, v6Networks = collector.GetMergedNetworks()
		return nil
	})

	if err := g.Wait(); err != nil {
		return err
	}

	// Записываем результаты
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

	data, err := client.Download(ctx, config.URL)
	if err != nil {
		logger.Error("Failed to download data for %s: %v", name, err)
		return nil
	}

	collector := NewNetworkCollector()
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		collector.AddNetwork(scanner.Text())
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

	// Собираем все ASN сервисы
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

	// Создаем множество всех нужных ASN для быстрого поиска
	allASNs := make(map[int][]string)
	for service, asns := range asnServices {
		for _, asn := range asns {
			allASNs[asn] = append(allASNs[asn], service)
		}
	}

	// Загружаем BGP данные
	bgpData, err := client.Download(ctx, bgpURL)
	if err != nil {
		logger.Error("Failed to download BGP data: %v", err)
		return err
	}

	// Парсим BGP данные и собираем CIDR по сервисам
	serviceCollectors := make(map[string]*NetworkCollector)
	for service := range asnServices {
		serviceCollectors[service] = NewNetworkCollector()
	}

	scanner := bufio.NewScanner(strings.NewReader(bgpData))
	lineCount := 0
	for scanner.Scan() {
		lineCount++
		if lineCount%100000 == 0 {
			logger.Info("Processed %d BGP lines", lineCount)
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		cidr := parts[0]
		asnStr := parts[len(parts)-1]

		asn, err := strconv.Atoi(asnStr)
		if err != nil {
			continue
		}

		if services, exists := allASNs[asn]; exists {
			for _, service := range services {
				serviceCollectors[service].AddNetwork(cidr)
			}
		}
	}

	logger.Info("Processed %d BGP lines total", lineCount)

	// Записываем результаты для каждого сервиса
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
    allV6Collector := NewNetworkCollector() // Отдельный коллектор для IPv6

    for _, service := range summary {
        // Читаем IPv4 файл
        v4File := getServiceCIDR4File(service)
        if data, err := os.ReadFile(v4File); err == nil {
            scanner := bufio.NewScanner(strings.NewReader(string(data)))
            for scanner.Scan() {
                allV4Collector.AddNetwork(scanner.Text())
            }
        } else {
            logger.Warn("Could not read IPv4 file for service %s: %v", service, err)
        }

        // Читаем IPv6 файл
        v6File := getServiceCIDR6File(service)
        if data, err := os.ReadFile(v6File); err == nil {
            scanner := bufio.NewScanner(strings.NewReader(string(data)))
            for scanner.Scan() {
                allV6Collector.AddNetwork(scanner.Text()) // Добавляем в IPv6 коллектор
            }
        } else {
            logger.Warn("Could not read IPv6 file for service %s: %v", service, err)
        }
    }

    // Получаем сети из КОРРЕКТНЫХ коллекторов
    mergedV4, _ := allV4Collector.GetMergedNetworks()
    _, mergedV6 := allV6Collector.GetMergedNetworks()

    // Создаем необходимые директории
    if err := os.MkdirAll(getCIDR4BasePath(), 0755); err != nil {
        return err
    }
    if err := os.MkdirAll(getCIDR6BasePath(), 0755); err != nil {
        return err
    }
    if err := os.MkdirAll(getCIDRsBasePath(), 0755); err != nil {
        return err
    }

    // Записываем summary файлы
    if err := writeNetworksToFile(getSummaryCIDR4File(), mergedV4); err != nil {
        return err
    }

    if err := writeNetworksToFile(getSummaryCIDR6File(), mergedV6); err != nil {
        return err
    }

    // Объединенный файл
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

	// Загружаем конфигурацию
	configData, err := os.ReadFile(CONFIG_FILE)
	if err != nil {
		logger.Error("Failed to read config file %s: %v", CONFIG_FILE, err)
		os.Exit(1)
	}

	var config Config
	if err := toml.Unmarshal(configData, &config); err != nil {
		logger.Error("Failed to parse config: %v", err)
		os.Exit(1)
	}

	// Создаем директории
	if err := setupDirectories(config.Services); err != nil {
		logger.Error("Failed to setup directories: %v", err)
		os.Exit(1)
	}

	// Создаем HTTP клиент
	client := NewHTTPClient(config.Settings.UserAgent)

	// Создаем контекст для URL сервисов
	urlCtx, urlCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer urlCancel()

	// Обрабатываем URL и single_url сервисы параллельно
	g, urlCtx := errgroup.WithContext(urlCtx)
	g.SetLimit(10) // Ограничиваем количество параллельных загрузок

	for name, serviceConfig := range config.Services {
		name, serviceConfig := name, serviceConfig // захватываем переменные
		switch serviceConfig.Type {
		case "url":
			g.Go(func() error {
				return processURLService(urlCtx, client, name, serviceConfig)
			})
		case "single_url":
			g.Go(func() error {
				return processSingleURLService(urlCtx, client, name, serviceConfig)
			})
		}
	}

	if err := g.Wait(); err != nil {
		logger.Error("Error processing URL services: %v", err)
		// Не завершаем программу, продолжаем с ASN сервисами
	}

	// Создаем отдельный контекст для ASN сервисов с большим таймаутом
	asnCtx, asnCancel := context.WithTimeout(context.Background(), 20*time.Minute)
	defer asnCancel()

	// Обрабатываем ASN сервисы
	if err := processASNServices(asnCtx, client, config.Services, config.Settings.BGPURL); err != nil {
		logger.Error("Error processing ASN services: %v", err)
		// Не завершаем программу, продолжаем с созданием summary
	}

	// Создаем summary
	if err := makeSummary(config.Settings.Summary); err != nil {
		logger.Error("Error creating summary: %v", err)
		os.Exit(1)
	}

	logger.Info("Subnet processing completed in %v", time.Since(start))
}