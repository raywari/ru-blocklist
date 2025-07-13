package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	apiURL         = "https://reestr.rublacklist.net/api/v3/domains/"
	domainRegex    = `^lordfilm\.[a-zA-Z0-9-]+$`
	sectionName    = "services.LordFilm"
	lordFilmFormat = `[%s]
domains = ["%s"]`
)

func main() {
	// Получаем абсолютный путь к TOML файлу (на два уровня выше для scripts/config/domain-scripts/)
	scriptDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Ошибка получения текущей директории: %v", err)
	}
	
	tomlPath := filepath.Join(scriptDir, "..", "parsing-domains.toml")
	tomlPath, err = filepath.Abs(tomlPath)
	if err != nil {
		log.Fatalf("Ошибка получения абсолютного пути: %v", err)
	}

	domains, err := getLordFilmDomains()
	if err != nil {
		log.Fatalf("Ошибка получения доменов: %v", err)
	}

	content, err := os.ReadFile(tomlPath)
	if err != nil && !os.IsNotExist(err) {
		log.Fatalf("Ошибка чтения TOML файла: %v", err)
	}

	updatedContent := updateLordFilmSection(string(content), domains)
	err = os.WriteFile(tomlPath, []byte(updatedContent), 0644)
	if err != nil {
		log.Fatalf("Ошибка записи TOML файла: %v", err)
	}

	fmt.Printf("Блок [%s] успешно обновлен в %s\n", sectionName, tomlPath)
}

func getLordFilmDomains() ([]string, error) {
	resp, err := http.Get(apiURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP запрос: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("неожиданный статус: %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("чтение ответа: %w", err)
	}

	var allDomains []string
	if err := json.Unmarshal(data, &allDomains); err != nil {
		return nil, fmt.Errorf("разбор JSON: %w", err)
	}

	return filterDomains(allDomains), nil
}

func filterDomains(domains []string) []string {
	re := regexp.MustCompile(domainRegex)
	var filtered []string
	for _, domain := range domains {
		if re.MatchString(domain) {
			filtered = append(filtered, domain)
		}
	}
	return filtered
}

func updateLordFilmSection(content string, domains []string) string {
	if len(domains) == 0 {
		return content
	}

	newSection := fmt.Sprintf(lordFilmFormat, sectionName, strings.Join(domains, `", "`))

	startIdx := strings.Index(content, "["+sectionName+"]")
	if startIdx == -1 {
		return strings.TrimSpace(content) + "\n\n" + newSection
	}

	endIdx := strings.Index(content[startIdx:], "\n\n")
	if endIdx == -1 {
		endIdx = len(content)
	} else {
		endIdx += startIdx
	}

	return content[:startIdx] + newSection + content[endIdx:]
}