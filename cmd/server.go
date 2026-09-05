// Интерфейс в браузере: только этот компьютер, наружу ничего не торчит.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"trustcheck/internal/check"
)

// Проверка одной ссылки для браузера.
func apiCheck(w http.ResponseWriter, req *http.Request) {
	if req.Method != "POST" {
		http.Error(w, "только POST", http.StatusMethodNotAllowed)
		return
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, 65536))
	if err != nil {
		http.Error(w, "не прочитал", http.StatusBadRequest)
		return
	}
	var in struct {
		Link string `json:"link"`
	}
	if err := json.Unmarshal(body, &in); err != nil || strings.TrimSpace(in.Link) == "" {
		http.Error(w, "нужна ссылка", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	r := checkOne(in.Link)
	_, histDir := linksSpot()
	appendHistory(histDir, r)
	data, _ := json.Marshal(r)
	_, _ = w.Write(data)
}

// Ключи из браузера: состояние всех и сохранение. Сами ключи наружу не отдаём.
func keyGet(which string) string {
	switch which {
	case "otx":
		return loadOTXKey()
	case "vt":
		return loadVTKey()
	default:
		return loadGSBKey()
	}
}

func keyValidate(which, key string) string {
	switch which {
	case "otx":
		return validateOTXKey(key)
	case "vt":
		return validateVTKey(key)
	default:
		return validateGSBKey(key)
	}
}

func keyFile(which string) string {
	switch which {
	case "otx":
		return "otx.key"
	case "vt":
		return "vt.key"
	default:
		return "gsb.key"
	}
}

func keyStore(which, key string) {
	switch which {
	case "otx":
		otxKey = key
	case "vt":
		vtKey = key
	default:
		gsbKey = key
	}
}

func looksLikeKey(k string) bool {
	return len(k) >= 10 && !strings.ContainsAny(k, " \t\n")
}

func apiKeys(w http.ResponseWriter, req *http.Request) {
	_, dir := linksSpot()
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if req.Method == "GET" {
		data, _ := json.Marshal(map[string]any{
			"google": keyGet("google") != "",
			"otx":    keyGet("otx") != "",
			"vt":     keyGet("vt") != "",
		})
		_, _ = w.Write(data)
		return
	}
	if req.Method != "POST" {
		http.Error(w, "не тот запрос", http.StatusMethodNotAllowed)
		return
	}
	body, _ := io.ReadAll(io.LimitReader(req.Body, 4096))
	var in struct {
		Which string `json:"which"`
		Key   string `json:"key"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		data, _ := json.Marshal(map[string]any{"ok": false, "error": "не прочитал ключ"})
		_, _ = w.Write(data)
		return
	}
	if in.Which != "google" && in.Which != "otx" && in.Which != "vt" {
		data, _ := json.Marshal(map[string]any{"ok": false, "error": "неизвестный ключ"})
		_, _ = w.Write(data)
		return
	}
	key := strings.TrimSpace(in.Key)
	if !looksLikeKey(key) {
		data, _ := json.Marshal(map[string]any{"ok": false, "error": "похоже, это не ключ — вставь целиком"})
		_, _ = w.Write(data)
		return
	}
	if msg := keyValidate(in.Which, key); msg != "" {
		data, _ := json.Marshal(map[string]any{"ok": false, "error": msg})
		_, _ = w.Write(data)
		return
	}
	if err := os.WriteFile(filepath.Join(dir, keyFile(in.Which)), []byte(key+"\n"), 0600); err != nil {
		data, _ := json.Marshal(map[string]any{"ok": false, "error": "не записался файл"})
		_, _ = w.Write(data)
		return
	}
	keyStore(in.Which, key)
	data, _ := json.Marshal(map[string]any{"ok": true})
	_, _ = w.Write(data)
}

func serve() {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/" {
			http.NotFound(w, req)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, pageHTML)
	})
	mux.HandleFunc("/api/check", apiCheck)
	mux.HandleFunc("/api/keys", apiKeys)
	mux.HandleFunc("/api/history", func(w http.ResponseWriter, req *http.Request) {
		_, dir := linksSpot()
		clear := req.Method == "DELETE"
		if req.Method == "POST" {
			body, _ := io.ReadAll(io.LimitReader(req.Body, 4096))
			clear = strings.Contains(string(body), `"action":"clear"`) || strings.Contains(string(body), `"action": "clear"`)
		}
		if clear {
			_ = os.WriteFile(filepath.Join(dir, "history.csv"), []byte{}, 0644)
			fmt.Println("Историю очистили через страницу.")
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			_, _ = io.WriteString(w, `{"ok":true}`)
			return
		}
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		data, _ := json.Marshal(readHistory(dir, 30))
		_, _ = w.Write(data)
	})
	mux.HandleFunc("/api/health", func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})
	mux.HandleFunc("/api/version", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		data, _ := json.Marshal(map[string]any{"version": check.AppVersion})
		_, _ = w.Write(data)
	})
	url := "http://" + check.ServeAddr() + "/"
	fmt.Println("Проверка доверия Pinterest, версия " + check.AppVersion)
	fmt.Println("Открываю страницу " + url)
	fmt.Println("Закрой это окно, чтобы остановить.")
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	if err := http.ListenAndServe(check.ServeAddr(), mux); err != nil {
		fmt.Println("Не запустилось:", err)
		fmt.Println("Возможно, уже открыта вторая копия — закрой её.")
	}
}
