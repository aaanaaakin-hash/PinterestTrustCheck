// Проверка условной лояльности Pinterest к домену.
// Важно простыми словами: у Pinterest нет открытого счёта доверия.
// Это наш собственный индекс 0-100 по открытым сигналам.
// Без аргументов читает links.txt рядом с программой и выдаёт таблицу.
// С аргументом проверяет одну ссылку. Только встроенные библиотеки Go.
package main

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"

	"trustcheck/internal/check"
)

const (
	timeoutMs    = 10000
	maxRedirects = 5
	maxBody      = 1024 * 1024
	maxPenalty   = 25
	cleanMax     = 15
)

// Страница интерфейса зашита внутрь программы, отдельных файлов не нужно.
//
//go:embed web/index.html
var pageHTML string

func main() {
	args := os.Args[1:]
	wantJSON := false
	links := []string{}
	for _, a := range args {
		if a == "--json" {
			wantJSON = true
			continue
		}
		if a == "--version" || a == "-v" {
			fmt.Println("Проверка доверия Pinterest, версия " + check.AppVersion)
			return
		}
		if a == "serve" {
			serve()
			return
		}
		links = append(links, a)
	}
	_, keyDir := linksSpot()
	ensureKeyTemplate(keyDir)

	// Одна ссылка аргументом — подробный разбор.
	if len(links) > 0 {
		r := checkOne(links[0])
		_, histDir := linksSpot()
		appendHistory(histDir, r)
		if wantJSON {
			data, _ := json.MarshalIndent(r, "", "  ")
			fmt.Println(string(data))
			return
		}
		printOne(r)
		fmt.Println("\nЧто сделать руками:")
		fmt.Println("  • В Pinterest нажми Создать → Пин, вставь ссылку в поле «Ссылка».")
		fmt.Println("    Ругается на спам — дело в домене. Принял молча — вопрос к аккаунту.")
		fmt.Println("  • Нажми F12, вкладка Сеть, и смотри ответ при сохранении пина — там текст причины.")
		return
	}

	// Без аргументов — пакет: все ссылки из links.txt, таблица + файл.
	linksFile, dir := linksSpot()
	list := loadLinks(linksFile)
	if len(list) == 0 {
		fmt.Println("В links.txt нет ссылок. Впиши по одной на строку и запусти снова.")
		return
	}
	fmt.Printf("Проверяю %d шт. из %s ...\n", len(list), linksFile)
	results := make([]check.Result, 0, len(list))
	for i, l := range list {
		fmt.Printf("[%d/%d] %s ...\n", i+1, len(list), l)
		r := checkOne(l)
		appendHistory(dir, r)
		results = append(results, r)
	}
	printTable(results)
	csv := writeCSV(dir, results)
	fmt.Printf("\nТаблица записана в %s\n", csv)
}
