package dast

import (
	"fmt"
	"net/http"
	"regexp"
	"sync"
	"time"

	"apiscanner/internal/report"
)

// описывает найденную проблему в API
type DastFinding struct {
	CheckName   string // Название проверки
	Description string // Описание ошибки
	Severty     string // Уровень риска: High, Medium, Low
}

func Run(targetURL string, rep *report.Report) {
	fmt.Printf("Подключение к целевому URL: %s\n\n", targetURL)

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// проверка доступности сервера
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		fmt.Printf("Ошибка формирования запроса: %v\n", err)
		return
	}
	req.Header.Set("User-Agent", "APISecurityScanner")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Сервер недоступен или превышен таймаут: %v\n", err)
		return
	}
	defer resp.Body.Close()

	fmt.Printf("Сервер ответил. Код состояния: %d\n\n", resp.StatusCode)

	//запуск тестов
	checkSecurityHeaders(resp.Header, rep)
	checkRateLimit(client, targetURL, rep)
	checkIDOR(client, targetURL, rep)
}

// проверяет наличие защитных заголовков в ответе сервера
func checkSecurityHeaders(headers http.Header, rep *report.Report) {
	fmt.Println("Проверка заголовков безопасности...")

	// список критичных заголовков, которые должны быть у безопасного API
	importantHeaders := map[string]string{
		"X-Content-Type-Options":    "Защита от Mime-Sniffing (должен быть 'nosniff')",
		"Strict-Transport-Security": "Принудительный HTTPS (HSTS)",
		"X-Frame-Options":           "Защита от Clickjacking",
	}

	for header, desc := range importantHeaders {
		if headers.Get(header) == "" {
			rep.Add(report.Vulnerability{
				Type:        "Security Misconfiguration",
				Location:    "Headers",
				Description: fmt.Sprintf("Отсутствует заголовок %s (%s)", header, desc),
				Severity:    "LOW",
			})
		}
	}

	// проверка CORS
	corsHeader := headers.Get("Access-Control-Allow-Origin")
	if corsHeader == "*" {
		rep.Add(report.Vulnerability{
			Type:        "Insecure CORS",
			Location:    "Headers",
			Description: "Заголовок Access-Control-Allow-Origin равен '*'",
			Severity:    "MEDIUM",
		})
	}
	fmt.Println()
}

// симулирует брутфорс/DoS атаку, отправляя 15 быстрых запросов
func checkRateLimit(client *http.Client, targetURL string, rep *report.Report) {
	fmt.Println("Проверка Rate Limiting...")

	// флаг изначально false, если хотя бы один запрос будет заблокирован сервером -> true
	rateLimitTriggered := false
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := 0; i < 15; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()

			req, err := http.NewRequest("GET", targetURL, nil)
			if err != nil {
				return
			}
			req.Header.Set("User-Agent", "APISecurityScanner")

			resp, err := client.Do(req)
			if err != nil {
				return
			}
			defer resp.Body.Close()

			if resp.StatusCode == 429 {
				mu.Lock()
				rateLimitTriggered = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if rateLimitTriggered {
		fmt.Println("Rate Limiting работает корректно (DoS/Брутфорса не будет :( )")
	} else {
		rep.Add(report.Vulnerability{
			Type:        "Missing Rate Limit",
			Location:    targetURL,
			Description: "Сервер обработал все 15 запросов без блокировки (риск DoS/Брутфорса)",
			Severity:    "MEDIUM",
		})
	}
	fmt.Println()
}

// проверка на Insecure Direct Object Reference
func checkIDOR(client *http.Client, targetURL string, rep *report.Report) {
	fmt.Println("Проверкаv IDOR (Broken Object Level Authorization)...")

	// ищем цифру в конце URL
	re := regexp.MustCompile(`/\d+$`)

	var testURL string
	if re.MatchString(targetURL) {
		// eсли URL заканчивается на число -> меняет его на заведомо чужой ID (9999)
		testURL = re.ReplaceAllString(targetURL, "/9999")
	} else {
		// eсли цифры нет -> принудительно добавляет ID в конец пути
		testURL = targetURL + "/1"
	}

	// отправка тестового запроса
	req, err := http.NewRequest("GET", testURL, nil)
	if err != nil {
		return
	}
	req.Header.Set("User-Agent", "APISecurityScanner")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Printf("Ошибка сети при проверке IDOR: %v\n", err)
		return
	}
	defer resp.Body.Close()

	// Анализ ответов от сервера
	if resp.StatusCode == 200 {
		rep.Add(report.Vulnerability{
			Type:        "BOLA/IDOR",
			Location:    testURL,
			Description: "Возможный IDOR! Сервер отдал данные (200 OK) по чужому ID",
			Severity:    "HIGH",
		})
	} else if resp.StatusCode == 401 || resp.StatusCode == 403 {
		fmt.Printf("IDOR маловероятен: сервер запретил доступ к %s (код %d).\n", testURL, resp.StatusCode)
	} else if resp.StatusCode == 404 {
		fmt.Printf("Объект не найден (404 OK). Сервер не выдает чужие данные по адресу %s.\n", testURL)
	} else {
		fmt.Printf("Неоднозначный ответ (код %d) для %s. Требуется ручной анализ.\n", resp.StatusCode, testURL)
	}
	fmt.Println()
}
