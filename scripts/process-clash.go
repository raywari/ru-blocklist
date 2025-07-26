package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// Настройки путей
var (
	dataDir         = "data/domains"
	groupsDir       = filepath.Join(dataDir, "groups")
	servicesDir     = filepath.Join(dataDir, "services")
	clashRulesDir   = filepath.Join("data", "rulesets", "clash-rules")
	
	mainFiles = []string{
		filepath.Join(dataDir, "domains-summary-no-yt.lst"),
		filepath.Join(dataDir, "domains-summary.lst"),
	}
	
	sourceExt = ".lst"
	targetExt = ".clash"
)

func main() {
	log.Println("Начинаем конвертацию доменов в Clash формат...")
	
	if err := os.MkdirAll(clashRulesDir, 0755); err != nil {
		log.Fatalf("Ошибка создания директории %s: %v", clashRulesDir, err)
	}
	
	cleanupClashFiles()
	
	processMainFiles()
	processDirectoryFiles(groupsDir)
	processDirectoryFiles(servicesDir)
	
	log.Println("Конвертация завершена!")
}

func processMainFiles() {
	log.Println("Обработка главных файлов...")
	
	for _, filePath := range mainFiles {
		if !fileExists(filePath) {
			log.Printf("Файл %s не найден, пропускаем", filePath)
			continue
		}
		
		log.Printf("Обрабатываем: %s", filePath)
		
		domains, err := readDomains(filePath)
		if err != nil {
			log.Printf("Ошибка чтения файла %s: %v", filePath, err)
			continue
		}
		
		clashRules := convertToClash(domains)
		
		fileName := strings.TrimSuffix(filepath.Base(filePath), sourceExt) + targetExt
		outputPath := filepath.Join(clashRulesDir, fileName)
		
		if err := writeClashRules(outputPath, clashRules); err != nil {
			log.Printf("Ошибка записи файла %s: %v", outputPath, err)
			continue
		}
		
		log.Printf("Создан файл: %s (%d правил)", outputPath, len(clashRules))
	}
}

func processDirectoryFiles(baseDir string) {
	if !dirExists(baseDir) {
		log.Printf("Директория %s не найдена, пропускаем", baseDir)
		return
	}
	
	log.Printf("Обработка директории: %s", baseDir)
	
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && strings.HasSuffix(path, sourceExt) {
			log.Printf("Обрабатываем: %s", path)
			
			domains, err := readDomains(path)
			if err != nil {
				log.Printf("Ошибка чтения файла %s: %v", path, err)
				return nil
			}
			
			clashRules := convertToClash(domains)
			
			outputPath := strings.TrimSuffix(path, sourceExt) + targetExt
			
			if err := writeClashRules(outputPath, clashRules); err != nil {
				log.Printf("Ошибка записи файла %s: %v", outputPath, err)
				return nil
			}
			
			log.Printf("Создан файл: %s (%d правил)", outputPath, len(clashRules))
		}
		
		return nil
	})
	
	if err != nil {
		log.Printf("Ошибка обхода директории %s: %v", baseDir, err)
	}
}

func readDomains(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	
	var domains []string
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "//") {
			continue
		}
		
		domains = append(domains, line)
	}
	
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	
	return domains, nil
}

func convertToClash(domains []string) []string {
	var clashRules []string
	
	for _, domain := range domains {
		cleanDomain := strings.TrimSpace(domain)
		
		if cleanDomain == "" {
			continue
		}
		
		if strings.HasPrefix(cleanDomain, "http://") {
			cleanDomain = strings.TrimPrefix(cleanDomain, "http://")
		}
		if strings.HasPrefix(cleanDomain, "https://") {
			cleanDomain = strings.TrimPrefix(cleanDomain, "https://")
		}
		
		if idx := strings.Index(cleanDomain, "/"); idx != -1 {
			cleanDomain = cleanDomain[:idx]
		}
		
		if idx := strings.Index(cleanDomain, ":"); idx != -1 {
			cleanDomain = cleanDomain[:idx]
		}
		
		if isIPAddress(cleanDomain) {
			continue
		}
		
		clashRule := "+." + cleanDomain
		clashRules = append(clashRules, clashRule)
	}
	
	return removeDuplicates(clashRules)
}

func writeClashRules(filePath string, rules []string) error {
	dir := filepath.Dir(filePath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()
	
	writer := bufio.NewWriter(file)
	defer writer.Flush()
	
	for _, rule := range rules {
		fmt.Fprintf(writer, "%s\n", rule)
	}
	
	return nil
}

func cleanupClashFiles() {
	log.Println("Удаление существующих .clash файлов...")
	
	cleanupDir(clashRulesDir)
	cleanupDir(groupsDir)
	cleanupDir(servicesDir)
}

func cleanupDir(baseDir string) {
	if !dirExists(baseDir) {
		return
	}
	
	err := filepath.Walk(baseDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		
		if !info.IsDir() && strings.HasSuffix(path, targetExt) {
			if err := os.Remove(path); err != nil {
				log.Printf("Ошибка удаления файла %s: %v", path, err)
			} else {
				log.Printf("Удален файл: %s", path)
			}
		}
		
		return nil
	})
	
	if err != nil {
		log.Printf("Ошибка очистки директории %s: %v", baseDir, err)
	}
}

func isIPAddress(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	
	for _, part := range parts {
		if len(part) == 0 || len(part) > 3 {
			return false
		}
		for _, char := range part {
			if char < '0' || char > '9' {
				return false
			}
		}
	}
	
	return true
}

func removeDuplicates(slice []string) []string {
	seen := make(map[string]bool)
	var result []string
	
	for _, item := range slice {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	
	return result
}

func fileExists(filePath string) bool {
	info, err := os.Stat(filePath)
	return err == nil && !info.IsDir()
}

func dirExists(dirPath string) bool {
	info, err := os.Stat(dirPath)
	return err == nil && info.IsDir()
}