package sast

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sync"
)

// словарь регулярных выражений для поиска секретов
var RegexRules = map[string]*regexp.Regexp{
	// Мессенджеры и соцсети
	"Telegram Bot Token": regexp.MustCompile(`[0-9]{8,10}:[a-zA-Z0-9_-]{35}`),
	"Discord Bot Token":  regexp.MustCompile(`[MN][A-Za-z\d]{23,25}\.[\w-]{6}\.[\w-]{27}`),
	"Slack Token":        regexp.MustCompile(`xox[baprs]-[0-9a-zA-Z]{10,48}`),
	"Slack Webhook":      regexp.MustCompile(`https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`),

	// Облачные провайдеры и инфраструктура
	"AWS Access Key":     regexp.MustCompile(`AKIA[0-9A-Z]{16}`),
	"Google API Key":     regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`),
	"Stripe Live Secret": regexp.MustCompile(`sk_live_[0-9a-zA-Z]{24,99}`),

	// Системы контроля версий
	"GitHub Token": regexp.MustCompile(`gh[pousr]_[a-zA-Z0-9]{36}`),

	// Криптография и аутентификация
	"JSON Web Token (JWT)": regexp.MustCompile(`ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`),
	"Private Key":          regexp.MustCompile(`-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----`),

	// Универсальный поиск паролей, секретов и API-ключей в конфигурациях
	"Generic Secret / API Key": regexp.MustCompile(`(?i)(api[_-]?key|apikey|secret|password|passwd|pwd|auth[_-]?token)["'\s:=]+([a-zA-Z0-9_\-\.]{12,64})`),
}

// Найденные уязвимости
type Finding struct {
	File  string // В каком файле нашли
	Line  int    // На какой строке
	Type  string // Тип (например, "Telegram Bot Token")
	Match string // Сам найденный кусок текста
}

func Run(targetDir string) {
	filesChan := make(chan string, 100) // Очередь файлов для сканирования
	var wg sync.WaitGroup               // Синхронизатор для ожидания всех воркеров

	// создаю 5 горутин
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go worker(filesChan, &wg)
	}

	// обход директории и отправка файлов в очередь
	err := filepath.WalkDir(targetDir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			dirName := d.Name()

			// Список папок, которые мы игнорируем
			ignoredDirs := map[string]bool{
				".git":         true,
				"node_modules": true,
				"vendor":       true,
				"dist":         true,
				"build":        true,
				".idea":        true,
				".vscode":      true,
			}
			if ignoredDirs[dirName] {
				return filepath.SkipDir // Пропускаем всю папку целиком
			}
			return nil
		}

		fileName := d.Name()
		if fileName == "apiscanner.exe" || fileName == "apiscanner" {
			return nil
		}

		ext := filepath.Ext(fileName)
		ignoredExtensions := map[string]bool{
			".exe":  true,
			".dll":  true,
			".zip":  true,
			".tar":  true,
			".gz":   true,
			".png":  true,
			".jpg":  true,
			".jpeg": true,
			".pdf":  true,
			".db":   true,
			".exe~": true,
		}

		if ignoredExtensions[ext] {
			return nil // Пропускаем этот файл
		}

		// отправка путя файла к воркерам
		filesChan <- path
		return nil
	})

	if err != nil {
		fmt.Printf("Ошибка чтения директории: %v\n", err)
	}

	close(filesChan)
	wg.Wait()
}

func worker(filesChan <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()

	// Воркер берет файлы из канала, пока канал не закроют
	for path := range filesChan {
		scanFile(path)
	}
}

// открывает файл, читает построчно и ищет регулярки
func scanFile(path string) {
	file, err := os.Open(path)
	if err != nil {
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	lineNumber := 1

	// Читаем файл строка за строкой
	for scanner.Scan() {
		lineText := scanner.Text()

		// Прогон строки через регулярки
		for ruleName, regex := range RegexRules {
			if regex.MatchString(lineText) {
				fmt.Printf("Найден %s!\n  Файл: %s:%d\n  Строка: %s\n\n", ruleName, path, lineNumber, lineText)
			}
		}
		lineNumber++
	}
}
