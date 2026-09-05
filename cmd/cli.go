// Печать в чёрное окно: одна ссылка и пакетная таблица.
package main

import (
	"fmt"
	"strings"

	"trustcheck/internal/check"
)

func printOne(r check.Result) {
	if r.Error != "" {
		fmt.Printf("\nСсылка: %s\nНе вышло: %s\n", r.Link, r.Error)
		return
	}
	fmt.Printf("\nСсылка: %s\n", r.Link)
	fmt.Printf("Итог: %d/100 — %s\n", r.Score, r.Verdict)
	fmt.Println("(это наш индекс, а не внутренняя цифра Pinterest)")
	fmt.Printf("Конечный адрес: %s\n\n", r.FinalURL)
	for _, p := range r.Checks {
		fmt.Printf("- %s: %d/%d — %s\n", p.Name, p.Got, p.Max, p.Note)
	}
	if len(r.Notes) > 0 {
		fmt.Println("\nПредупреждения:")
		for _, n := range r.Notes {
			fmt.Printf("  - %s\n", n)
		}
	}
	if len(r.Info) > 0 {
		fmt.Println("\nСправка:")
		for _, s := range r.Info {
			fmt.Printf("  - %s\n", s)
		}
	}
	fmt.Println("\nПочитай сам:")
	for _, l := range check.ReadLinks(r.Host) {
		fmt.Printf("  - %s: %s\n", l.Name, l.URL)
	}
}

func printTable(list []check.Result) {
	fmt.Printf("\n%-6s %-10s %s\n", "БАЛЛ", "СТАТУС", "ССЫЛКА")
	fmt.Println(strings.Repeat("-", 70))
	for _, r := range list {
		if r.Error != "" {
			fmt.Printf("%-6s %-10s %s (%s)\n", "--", "ОШИБКА", r.Link, r.Error)
			continue
		}
		fmt.Printf("%-6d %-10s %s\n", r.Score, r.Word, r.Link)
	}
	fmt.Println(strings.Repeat("-", 70))
	fmt.Println("(это наш индекс, а не внутренняя цифра Pinterest)")
}
