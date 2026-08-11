package main

import (
	"flag"
	"fmt"
	"os"

	"apiscanner/internal/dast"
	"apiscanner/internal/report"
	"apiscanner/internal/sast"
)

// хранит параметры запуска сканера
type Config struct {
	Mode       string
	Path       string
	TargetURL  string
	OutputFile string
}

// проверка логики валидации
func validateConfig(cfg Config) error {
	switch cfg.Mode {
	case "sast":
		if cfg.Path == "" {
			return fmt.Errorf("для режима SAST необходимо указать -path")
		}

	case "dast":
		if cfg.TargetURL == "" {
			return fmt.Errorf("для режима DAST необходимо указать -url")
		}

	case "all":
		if cfg.Path == "" || cfg.TargetURL == "" {
			return fmt.Errorf("для режима ALL нужно указать и -path, и -url")
		}

	default:
		return fmt.Errorf("неизвестный режим: %s (допустимы: sast, dast, all)", cfg.Mode)
	}
	return nil
}

func main() {
	cfg := Config{}

	// CLI флаги
	flag.StringVar(&cfg.Mode, "mode", "sast", "Режим сканирования: sast или dast")
	flag.StringVar(&cfg.Path, "path", "", "Путь к директории для SAST сканирования")
	flag.StringVar(&cfg.TargetURL, "url", "", "URL API для DAST сканирования")
	flag.StringVar(&cfg.OutputFile, "output", "", "Файл для сохранения отчета")

	flag.Parse()

	rep := report.New()

	// ф-ия проверки
	if err := validateConfig(cfg); err != nil {
		fmt.Printf("[!] Ошибка аргументов: %v\n\n", err)
		flag.Usage() // Выводит справку по всем флагам
		os.Exit(1)
	}

	fmt.Println("==========================================")
	fmt.Println("           API Security Scanner           ")
	fmt.Println("==========================================")

	// запуск модулей
	switch cfg.Mode {
	case "sast":
		runSAST(cfg.Path, rep)
	case "dast":
		runDAST(cfg.TargetURL, rep)
	case "all":
		runSAST(cfg.Path, rep)
		runDAST(cfg.TargetURL, rep)
	}
	rep.PrintTable()
	if cfg.OutputFile != "" {
		rep.ExportJSON(cfg.OutputFile)
		fmt.Println("Файл успешно сохранен")
	}

}

func runSAST(path string, rep *report.Report) {
	fmt.Printf("Запуск SAST сканирования в директории: %s\n", path)
	sast.Run(path, rep)
	fmt.Println("\n SAST сканирование завершено.")
}

func runDAST(targetURL string, rep *report.Report) {
	fmt.Printf("Запуск DAST сканирования целевого URL: %s\n", targetURL)
	dast.Run(targetURL, rep)
	fmt.Println("\n DAST сканирование завершено.")
}
