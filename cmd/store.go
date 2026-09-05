// Файлы и ключ: всё рядом с кнопками, вопросов не задаём.
package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"trustcheck/internal/check"
)

// Ключ Google Safe Browsing: переменная окружения или файл gsb.key.
// Читаем один раз. Нет ключа — тихо пропускаем проверку.
var gsbOnce sync.Once
var gsbKey string

func loadGSBKey() string {
	gsbOnce.Do(func() {
		if k := strings.TrimSpace(os.Getenv("PINTEREST_GSB_KEY")); k != "" {
			gsbKey = k
			return
		}
		paths := []string{"gsb.key"}
		if ex, err := os.Executable(); err == nil {
			paths = append(paths, filepath.Join(filepath.Dir(ex), "gsb.key"))
		}
		for _, p := range paths {
			if data, err := os.ReadFile(p); err == nil {
				if k := strings.TrimSpace(string(data)); k != "" && !strings.HasPrefix(k, "#") {
					gsbKey = k
					return
				}
			}
		}
	})
	return gsbKey
}

// Дописывает итог в историю. Файл не растёт бесконечно — держим хвост.
func appendHistory(dir string, r check.Result) {
	if r.Error != "" {
		return
	}
	p := filepath.Join(dir, "history.csv")
	clean := func(s string) string {
		s = strings.ReplaceAll(s, ";", ",")
		return strings.ReplaceAll(s, "\n", " ")
	}
	line := fmt.Sprintf("%s;%s;%d;%s;%s;%s;%s\n",
		time.Now().Format("2006-01-02 15:04:05"), clean(r.Link), r.Score, r.Word,
		clean(r.FinalURL), check.CompactChecks(r.Checks), clean(strings.Join(r.Notes, " | ")))
	fh, err := os.OpenFile(p, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return
	}
	_, _ = fh.WriteString(line)
	_ = fh.Close()
	if data, err := os.ReadFile(p); err == nil {
		lines := strings.Split(string(data), "\n")
		if len(lines) > 5000 {
			_ = os.WriteFile(p, []byte(strings.Join(lines[len(lines)-4000:], "\n")), 0644)
		}
	}
}

// Последние строки истории для браузера.
func readHistory(dir string, n int) []map[string]string {
	data, err := os.ReadFile(filepath.Join(dir, "history.csv"))
	if err != nil {
		return []map[string]string{}
	}
	lines := []string{}
	for _, l := range strings.Split(string(data), "\n") {
		if s := strings.TrimSpace(l); s != "" {
			lines = append(lines, s)
		}
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	out := make([]map[string]string, 0, len(lines))
	for _, l := range lines {
		parts := strings.SplitN(l, ";", 7)
		row := map[string]string{"time": "", "link": "", "score": "", "word": "", "detail": "", "notes": ""}
		if len(parts) > 0 {
			row["time"] = parts[0]
		}
		if len(parts) > 1 {
			row["link"] = parts[1]
		}
		if len(parts) > 2 {
			row["score"] = parts[2]
		}
		if len(parts) > 3 {
			row["word"] = parts[3]
		}
		if len(parts) > 5 {
			row["detail"] = parts[5]
		}
		if len(parts) > 6 {
			row["notes"] = parts[6]
		}
		out = append(out, row)
	}
	return out
}

// Где лежат links.txt и куда писать итоги: сначала текущая папка
// (там лежат кнопки), потом папка программы. Вопросов не задаёт.
func linksSpot() (linksFile, dir string) {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd)
	}
	if ex, err := os.Executable(); err == nil {
		if d := filepath.Dir(ex); d != "" {
			candidates = append(candidates, d)
		}
	}
	for _, d := range candidates {
		p := filepath.Join(d, "links.txt")
		if _, err := os.Stat(p); err == nil {
			return p, d
		}
	}
	if len(candidates) > 0 {
		return filepath.Join(candidates[0], "links.txt"), candidates[0]
	}
	return "links.txt", "."
}

const sampleLinks = "amazon.com\nsites.google.com\nbit.ly\n"

// Читает ссылки из файла. Пустые строки и строки с # пропускает.
// Если файла нет — создаёт образец и проверяет его. Вопросов не задаёт.
func loadLinks(path string) []string {
	data, err := os.ReadFile(path)
	if err != nil {
		_ = os.WriteFile(path, []byte(sampleLinks), 0644)
		data = []byte(sampleLinks)
		fmt.Println("Файла links.txt не было — создал образец. Впиши туда свои ссылки, по одной на строку.")
	}
	out := []string{}
	for _, line := range strings.Split(string(data), "\n") {
		s := strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Если файла gsb.key нет — создаём образец с подсказкой. Строки с # не считаются ключом.
func ensureKeyTemplate(dir string) {
	p := filepath.Join(dir, "gsb.key")
	if _, err := os.Stat(p); err == nil {
		return
	}
	text := "# Ключ Google Safe Browsing (не обязателен, без него программа работает).\n" +
		"# Как получить: console.cloud.google.com → проект → Safe Browsing API → Включить →\n" +
		"# Учётные данные → Создать → Ключ API. Вставь ключ вместо этой строки одной строкой.\n"
	_ = os.WriteFile(p, []byte(text), 0644)
}

// Пишет итоги в results.csv рядом с программой.
func writeCSV(dir string, list []check.Result) string {
	var b strings.Builder
	b.WriteString("ссылка;балл;статус;конечный адрес;заметки\n")
	esc := func(s string) string {
		s = strings.ReplaceAll(s, "\"", "'")
		return "\"" + s + "\""
	}
	for _, r := range list {
		if r.Error != "" {
			fmt.Fprintf(&b, "%s;--;%s;;%s\n", esc(r.Link), "ОШИБКА", esc(r.Error))
			continue
		}
		fmt.Fprintf(&b, "%s;%d;%s;%s;%s\n",
			esc(r.Link), r.Score, esc(r.Word), esc(r.FinalURL), esc(strings.Join(r.Notes, " | ")))
	}
	p := filepath.Join(dir, "results.csv")
	_ = os.WriteFile(p, []byte(b.String()), 0644)
	return p
}
