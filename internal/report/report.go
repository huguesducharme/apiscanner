package report

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"text/tabwriter"
)

// универсальная структура для SAST и DAST находок
type Vulnerability struct {
	Type        string `json:"type"`        // Тип угрозы (например, "Telegram Bot Token" или "Insecure CORS")
	Location    string `json:"location"`    // Где нашли: путь к файлу (cmd/main.go:15) или URL (/api/users/9999)
	Description string `json:"description"` // Детали и советы по устранению
	Severity    string `json:"severity"`    // Риск: HIGH, MEDIUM, LOW
}

// хранит все уязвимости и защищает их мьютексом от состояния гонки
type Report struct {
	mu    sync.Mutex
	Vulns []Vulnerability `json:"vulnerabilities"`
}

// конструктор для создания нового отчета
func New() *Report {
	return &Report{
		Vulns: make([]Vulnerability, 0),
	}
}

// безопасно добавляет находку в список (работает из любых горутин)
func (r *Report) Add(v Vulnerability) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.Vulns = append(r.Vulns, v)
}

// выводит красивую ASCII-таблицу в терминал
func (r *Report) PrintTable() {
	if len(r.Vulns) == 0 {
		fmt.Println("\n[+] Сканирование завершено. Уязвимостей не найдено!")
		return
	}

	fmt.Printf("\n  НАЙДЕНО УЯЗВИМОСТЕЙ: %d\n\n", len(r.Vulns))

	// tabwriter (вывод в консоль, минимальная ширина, табы, отступы, разделитель ' ')
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 3, ' ', tabwriter.TabIndent)

	fmt.Fprintln(w, "RISK\tTYPE\tLOCATION\tDESCRIPTION")
	fmt.Fprintln(w, "----\t----\t--------\t-----------")

	for _, v := range r.Vulns {

		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", v.Severity, v.Type, v.Location, v.Description)
	}

	w.Flush() // смыв буфера чтобы табл. нарисовалась
	fmt.Println()
}

// сохраняет отчет в JSON-файл для интеграции с CI/CD
func (r *Report) ExportJSON(filename string) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(r)
}
