// Чистая логика без сети: разбор ввода, подсчёт, вердикты.
// Здесь нет запросов наружу, поэтому всё покрыто тестами.
package check

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"regexp"
	"strings"
)

// Номер версии — показывается на странице и в консоли, чтобы не путать сборки.
const AppVersion = "1.5.0"

var (
	reMetaRefresh = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']?refresh`)
	reLocReplace  = regexp.MustCompile(`(?i)location\.replace\s*\(\s*["']https?:`)
	reWinLoc      = regexp.MustCompile(`(?i)window\.location\s*=\s*["']https?:`)
)

// Одна строка итога по проверке.
type CheckPart struct {
	Name string `json:"name"`
	Got  int    `json:"got"`
	Max  int    `json:"max"`
	Note string `json:"note"`
}

// Итог проверки одной ссылки.
type Result struct {
	OK        bool        `json:"ok"`
	Link      string      `json:"link"`
	Host      string      `json:"host,omitempty"`
	FinalURL  string      `json:"finalUrl,omitempty"`
	Score     int         `json:"score,omitempty"`
	Verdict   string      `json:"verdict,omitempty"`
	Word      string      `json:"word,omitempty"`
	Important string      `json:"important,omitempty"`
	Checks    []CheckPart `json:"checks,omitempty"`
	Hops      []string    `json:"hops,omitempty"`
	Notes     []string    `json:"notes,omitempty"`
	Info      []string    `json:"info,omitempty"`
	Error     string      `json:"error,omitempty"`
}

// Доменные метки проверяем вручную: Go не умеет заглядывания в шаблонах.
func ValidHost(s string) bool {
	if len(s) < 1 || len(s) > 253 {
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for i := 0; i < len(label); i++ {
			c := label[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}

// Приводит ввод к паре домен + стартовая ссылка. Ввод считаем недоверенным.
func ToStartURL(raw string) (host, start string, err error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", "", fmt.Errorf("пусто")
	}
	if len(s) > 2000 {
		return "", "", fmt.Errorf("длинно")
	}
	if strings.ContainsAny(s, " \t\\") {
		return "", "", fmt.Errorf("лишние символы")
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return "", "", fmt.Errorf("ошибка разбора")
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return "", "", fmt.Errorf("нужна обычная ссылка")
	}
	if u.User != nil {
		return "", "", fmt.Errorf("ссылки с логином нельзя")
	}
	host, err = CleanHost(u.Hostname())
	if err != nil {
		return "", "", err
	}
	path := u.EscapedPath()
	if path == "" {
		path = "/"
	}
	start = "https://" + host + path
	if u.RawQuery != "" {
		start += "?" + u.RawQuery
	}
	return host, start, nil
}

// Чистит голый домен.
func CleanHost(h string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(h))
	s = strings.Trim(s, ".")
	if len(s) < 3 || len(s) > 253 {
		return "", fmt.Errorf("не домен")
	}
	if strings.ContainsAny(s, " \t_\\/@") {
		return "", fmt.Errorf("лишние символы")
	}
	if s == "localhost" {
		return "", fmt.Errorf("локальное нельзя")
	}
	if !strings.Contains(s, ".") {
		return "", fmt.Errorf("нужна точка")
	}
	if !ValidHost(s) {
		return "", fmt.Errorf("ошибка написания")
	}
	if ip := net.ParseIP(s); ip != nil {
		if IsPrivateIP(ip) {
			return "", fmt.Errorf("внутренний адрес")
		}
		return s, nil
	}
	return s, nil
}

func IsPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

// Один и тот же сайт (amazon.com и www.amazon.com) — это не маскировка.
func SameSite(a, b string) bool {
	if a == "" || b == "" || a == b {
		return true
	}
	return strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

func HostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func VerdictOf(score int) (string, string) {
	switch {
	case score >= 80:
		return "Зелёный: домен спокойный, таким обычно пользуются без просадок", "ЗЕЛЁНЫЙ"
	case score >= 60:
		return "Жёлтый: пользоваться можно, но следи за показами первых пинов", "ЖЁЛТЫЙ"
	case score >= 40:
		return "Оранжевый: риск просадки показов, готовь запасной домен", "ОРАНЖЕВЫЙ"
	default:
		return "Красный: высокий риск блокировки ссылок и обрубания показов", "КРАСНЫЙ"
	}
}

func HasAny(s string, marks []string) bool {
	for _, m := range marks {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func HasSuffixAny(s string, list []string) bool {
	for _, m := range list {
		if s == m || strings.HasSuffix(s, "."+m) {
			return true
		}
	}
	return false
}

// Ищет настоящий переброс (маскировку), а не обычный код сайта.
func HasJsRedirect(body string) string {
	b := body
	if len(b) > 20000 {
		b = b[:20000]
	}
	if reMetaRefresh.MatchString(b) {
		return "meta-refresh"
	}
	if reLocReplace.MatchString(b) {
		return "js-redirect"
	}
	if len(body) < 15000 && reWinLoc.MatchString(b) {
		return "js-redirect"
	}
	return ""
}

// Короткая запись баллов по пунктам, чтобы ловить скачки: R30 T25 S10 H1 A8 C15.
func CompactChecks(parts []CheckPart) string {
	code := map[string]string{
		"Редиректы": "R", "Шифрование": "T", "Скорость": "S",
		"Заголовки": "H", "Возраст": "A", "Без хвостов": "C",
	}
	out := []string{}
	for _, p := range parts {
		if c, ok := code[p.Name]; ok {
			out = append(out, fmt.Sprintf("%s%d", c, p.Got))
		}
	}
	return strings.Join(out, " ")
}

// Адрес страницы: обычно стандартный, но порт можно сменить переменной PINTEREST_PORT.
func ServeAddr() string {
	const defServeAddr = "127.0.0.1:18743"
	if p := strings.TrimSpace(os.Getenv("PINTEREST_PORT")); p != "" {
		ok := len(p) >= 2 && len(p) <= 5
		for _, c := range p {
			if c < '0' || c > '9' {
				ok = false
			}
		}
		if ok {
			return "127.0.0.1:" + p
		}
	}
	return defServeAddr
}
