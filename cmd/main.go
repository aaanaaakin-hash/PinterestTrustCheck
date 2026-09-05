// Проверка условной лояльности Pinterest к домену.
// Важно простыми словами: у Pinterest нет открытого счёта доверия.
// Это наш собственный индекс 0-100 по открытым сигналам.
// Без аргументов читает links.txt рядом с программой и выдаёт таблицу.
// С аргументом проверяет одну ссылку. Только встроенные библиотеки Go.
package main

import (
	"context"
	"crypto/tls"
	_ "embed"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	timeoutMs    = 10000
	maxRedirects = 5
	maxBody      = 1024 * 1024
	maxPenalty   = 25
	cleanMax     = 15
	serveAddr    = "127.0.0.1:18743"
)

// Страница интерфейса зашита внутрь программы, отдельных файлов не нужно.
//
//go:embed web/index.html
var pageHTML string

var (
	uaMobile  = "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1"
	uaBrowser = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
	uaBot     = "Mozilla/5.0 (compatible; Pinterestbot/1.0; +https://www.pinterest.com/bot.html)"

	freeHosts = []string{
		"sites.google.com", "blogspot.com", "wixsite.com", "weebly.com",
		"wordpress.com", "tilda.ws", "canva.site", "linktr.ee", "jimdofree.com",
		"workers.dev", "pages.dev", "vercel.app", "netlify.app", "github.io",
		"gitlab.io", "webflow.io", "notion.site", "framer.website",
		"mystrikingly.com", "bubbleapps.io",
	}
	shorteners = []string{
		"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
		"buff.ly", "rebrand.ly", "cutt.ly", "shor.by", "clck.ru",
	}
	affMarks = []string{
		"aff", "aff_id", "affiliate", "subid", "clickid", "fbclid", "gclid", "utm_",
	}

	reMetaRefresh = regexp.MustCompile(`(?i)<meta[^>]+http-equiv=["']?refresh`)
	reLocReplace  = regexp.MustCompile(`(?i)location\.replace\s*\(\s*["']https?:`)
	reWinLoc      = regexp.MustCompile(`(?i)window\.location\s*=\s*["']https?:`)
)

// Доменные метки проверяем вручную: Go не умеет заглядывания в шаблонах.
func validHost(s string) bool {
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

// Одна строка итога по проверке.
type checkPart struct {
	Name string `json:"name"`
	Got  int    `json:"got"`
	Max  int    `json:"max"`
	Note string `json:"note"`
}

// Итог проверки одной ссылки.
type result struct {
	OK        bool        `json:"ok"`
	Link      string      `json:"link"`
	Host      string      `json:"host,omitempty"`
	FinalURL  string      `json:"finalUrl,omitempty"`
	Score     int         `json:"score,omitempty"`
	Verdict   string      `json:"verdict,omitempty"`
	Word      string      `json:"word,omitempty"`
	Important string      `json:"important,omitempty"`
	Checks   []checkPart `json:"checks,omitempty"`
	Hops     []string    `json:"hops,omitempty"`
	Notes    []string    `json:"notes,omitempty"`
	Info     []string    `json:"info,omitempty"`
	Error    string      `json:"error,omitempty"`
}

// Приводит ввод к паре домен + стартовая ссылка. Ввод считаем недоверенным.
func toStartURL(raw string) (host, start string, err error) {
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
	host, err = cleanHost(u.Hostname())
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
func cleanHost(h string) (string, error) {
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
	if !validHost(s) {
		return "", fmt.Errorf("ошибка написания")
	}
	if ip := net.ParseIP(s); ip != nil {
		if isPrivateIP(ip) {
			return "", fmt.Errorf("внутренний адрес")
		}
		return s, nil
	}
	return s, nil
}

func isPrivateIP(ip net.IP) bool {
	return ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsUnspecified()
}

// Домен должен находиться и вести наружу (защита от подмены).
// Возвращает первый внешний адрес — он нужен для справки о хостинге.
func resolveGuard(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateIP(ip) {
			return "", fmt.Errorf("внутренний")
		}
		return ip.String(), nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeoutMs*time.Millisecond)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("не находится")
	}
	for _, a := range addrs {
		if !isPrivateIP(a.IP) {
			return a.IP.String(), nil
		}
	}
	return "", fmt.Errorf("ведёт внутрь")
}

type hopOut struct {
	url    string
	status int
	to     string
}

type fetchOut struct {
	hops    []hopOut
	headers http.Header
	body    string
	ms      int64
	stopped bool
}

// Один запрос без авторедиректов, с лимитом размера и таймаутом.
func fetchOnce(client *http.Client, urlStr, ua string) (int, http.Header, string, string, int64, error) {
	t0 := time.Now()
	req, err := http.NewRequest("GET", urlStr, nil)
	if err != nil {
		return 0, nil, "", "", 0, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "text/html,*/*")
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, "", "", time.Since(t0).Milliseconds(), err
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, maxBody))
	if err != nil {
		return 0, nil, "", "", 0, err
	}
	return res.StatusCode, res.Header, res.Header.Get("Location"), string(data), time.Since(t0).Milliseconds(), nil
}

// Идёт по цепочке переадресаций вручную и записывает каждый шаг.
func fetchChain(start, ua string) fetchOut {
	client := &http.Client{
		Timeout: timeoutMs * time.Millisecond,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	out := fetchOut{}
	cur := start
	for i := 0; i <= maxRedirects; i++ {
		st, hdr, loc, body, ms, err := fetchOnce(client, cur, ua)
		if err != nil {
			return out
		}
		out.hops = append(out.hops, hopOut{url: cur, status: st, to: loc})
		out.ms += ms
		out.headers = hdr
		out.body = body
		if (st == 301 || st == 302 || st == 303 || st == 307 || st == 308) && loc != "" {
			next, err := url.Parse(loc)
			if err != nil {
				return out
			}
			base, _ := url.Parse(cur)
			cur = base.ResolveReference(next).String()
			continue
		}
		return out
	}
	out.stopped = true
	return out
}

// Сведения о сертификате и версии шифрования.
type tlsOut struct {
	ok       bool
	protocol string
	daysLeft int
}

func tlsInfo(host string) tlsOut {
	dialer := &net.Dialer{Timeout: timeoutMs * time.Millisecond}
	t0 := time.Now()
	_ = t0
	conn, err := tls.DialWithDialer(dialer, "tcp", host+":443", &tls.Config{ServerName: host})
	if err != nil {
		return tlsOut{}
	}
	defer conn.Close()
	st := conn.ConnectionState()
	proto := ""
	switch st.Version {
	case tls.VersionTLS13:
		proto = "TLSv1.3"
	case tls.VersionTLS12:
		proto = "TLSv1.2"
	default:
		proto = "старый TLS"
	}
	days := -999
	if len(st.PeerCertificates) > 0 {
		days = int(time.Until(st.PeerCertificates[0].NotAfter).Hours() / 24)
	}
	return tlsOut{ok: true, protocol: proto, daysLeft: days}
}

// Возраст домена через открытый RDAP. Может не ответить — тогда нейтрально.
func rdapAge(host string) *int {
	client := &http.Client{Timeout: timeoutMs * time.Millisecond}
	req, _ := http.NewRequest("GET", "https://rdap.org/domain/"+url.PathEscape(host), nil)
	req.Header.Set("User-Agent", uaBrowser)
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer res.Body.Close()
	data, err := io.ReadAll(io.LimitReader(res.Body, 200000))
	if err != nil {
		return nil
	}
	var doc struct {
		Events []struct {
			Action string `json:"eventAction"`
			Date   string `json:"eventDate"`
		} `json:"events"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil
	}
	for _, e := range doc.Events {
		if e.Action == "registration" && e.Date != "" {
			t, err := time.Parse(time.RFC3339, e.Date)
			if err != nil {
				return nil
			}
			m := int(time.Since(t).Hours() / 730)
			return &m
		}
	}
	return nil
}

// Ищет настоящий переброс (маскировку), а не обычный код сайта.
func hasJsRedirect(body string) string {
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

// Один и тот же сайт (amazon.com и www.amazon.com) — это не маскировка.
func sameSite(a, b string) bool {
	if a == "" || b == "" || a == b {
		return true
	}
	return strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

func hostOf(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

func verdictOf(score int) (string, string) {
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

func hasAny(s string, marks []string) bool {
	for _, m := range marks {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

func hasSuffixAny(s string, list []string) bool {
	for _, m := range list {
		if s == m || strings.HasSuffix(s, "."+m) {
			return true
		}
	}
	return false
}

// Полная проверка одной ссылки.
func checkOne(link string) result {
	r := result{Link: link, Notes: []string{}, Checks: []checkPart{}, Hops: []string{}}
	host, start, err := toStartURL(link)
	if err != nil {
		r.Error = "Проверь написание ссылки"
		return r
	}
	r.Host = host

	if ip, err := resolveGuard(host); err != nil {
		r.Host = host
		r.Error = "Домен не находится, проверять нечего"
		return r
	} else {
		r.Info = append(r.Info, hostingInfo(ip))
	}

	// Цепочка переадресаций (главное для Pinterest).
	f := fetchChain(start, uaMobile)
	finalURL := start
	if len(f.hops) > 0 {
		finalURL = f.hops[len(f.hops)-1].url
	}
	r.FinalURL = finalURL
	for _, h := range f.hops {
		r.Hops = append(r.Hops, fmt.Sprintf("%d %s", h.status, h.url))
	}
	if len(f.hops) == 0 {
		r.Checks = append(r.Checks, checkPart{Name: "Редиректы", Got: 0, Max: 30, Note: "сайт не открылся за 10 секунд"})
		r.Notes = append(r.Notes, "Сайт не отвечает. Pinterest тоже сочтёт его небезопасным.")
	} else {
		count := len(f.hops) - 1
		hopHosts := []string{}
		for _, h := range f.hops {
			hopHosts = append(hopHosts, hostOf(h.url))
		}
		cross := false
		for _, h := range hopHosts {
			if !sameSite(h, hopHosts[0]) {
				cross = true
			}
		}
		switch {
		case f.stopped:
			r.Checks = append(r.Checks, checkPart{Name: "Редиректы", Got: 0, Max: 30, Note: fmt.Sprintf("больше %d прыжков — Pinterest такое режет", maxRedirects)})
		case count == 0:
			r.Checks = append(r.Checks, checkPart{Name: "Редиректы", Got: 30, Max: 30, Note: "прямой адрес без прыжков — идеально"})
		case count == 1 && !cross:
			r.Checks = append(r.Checks, checkPart{Name: "Редиректы", Got: 25, Max: 30, Note: "один прыжок внутри своего сайта — нормально"})
		case count == 1:
			r.Checks = append(r.Checks, checkPart{Name: "Редиректы", Got: 14, Max: 30, Note: "один прыжок на другой домен — лучше прямую ссылку"})
		case count == 2:
			r.Checks = append(r.Checks, checkPart{Name: "Редиректы", Got: 8, Max: 30, Note: "два прыжка — уже риск просадки"})
		default:
			r.Checks = append(r.Checks, checkPart{Name: "Редиректы", Got: 0, Max: 30, Note: fmt.Sprintf("%d прыжка — Pinterest такое обычно режет", count)})
		}
		if cross {
			r.Notes = append(r.Notes, "Адрес по пути меняет домен — для Pinterest это плохой знак.")
		}
		lastStatus := f.hops[len(f.hops)-1].status
		if lastStatus >= 400 {
			r.Notes = append(r.Notes, fmt.Sprintf("Страница отвечает ошибкой %d — чини страницу, Pinterest битые ссылки не любит.", lastStatus))
			cur := &r.Checks[len(r.Checks)-1]
			if cur.Got > 10 {
				cur.Got = 10
			}
			cur.Note += fmt.Sprintf(", но страница битая (%d)", lastStatus)
		}
	}

	// Шифрование.
	finalHost := hostOf(finalURL)
	if finalHost == "" {
		finalHost = host
	}
	t := tlsInfo(finalHost)
	switch {
	case t.ok && (t.protocol == "TLSv1.3" || t.protocol == "TLSv1.2") && t.daysLeft > 30:
		r.Checks = append(r.Checks, checkPart{Name: "Шифрование", Got: 25, Max: 25, Note: "сертификат в порядке (" + t.protocol + ")"})
	case t.ok && t.daysLeft > 0:
		r.Checks = append(r.Checks, checkPart{Name: "Шифрование", Got: 12, Max: 25, Note: "сертификат есть, но слабый или скоро кончится"})
		r.Notes = append(r.Notes, "Проверь срок сертификата, скоро кончится.")
	default:
		r.Checks = append(r.Checks, checkPart{Name: "Шифрование", Got: 0, Max: 25, Note: "сертификат битый или его нет — Pinterest блочит"})
	}

	// Скорость.
	switch {
	case f.ms < 600:
		r.Checks = append(r.Checks, checkPart{Name: "Скорость", Got: 10, Max: 10, Note: fmt.Sprintf("отвечает за %d мс — быстро", f.ms)})
	case f.ms < 1500:
		r.Checks = append(r.Checks, checkPart{Name: "Скорость", Got: 6, Max: 10, Note: fmt.Sprintf("отвечает за %d мс — средне", f.ms)})
	default:
		r.Checks = append(r.Checks, checkPart{Name: "Скорость", Got: 2, Max: 10, Note: fmt.Sprintf("отвечает за %d мс — медленно, Pinterest не любит", f.ms)})
	}

	// Заголовки — мелочь для фона.
	hg := 0
	if f.headers.Get("Content-Type") != "" {
		hg++
	}
	if f.headers.Get("X-Content-Type-Options") != "" {
		hg++
	}
	if f.headers.Get("X-Frame-Options") != "" || f.headers.Get("Content-Security-Policy") != "" {
		hg++
	}
	if f.headers.Get("Strict-Transport-Security") != "" {
		hg++
	}
	if f.headers.Get("Referrer-Policy") != "" {
		hg++
	}
	hnote := "мелочь для фона, на Pinterest почти не влияет"
	if hg >= 4 {
		hnote = "порядок"
	}
	r.Checks = append(r.Checks, checkPart{Name: "Заголовки", Got: hg, Max: 5, Note: hnote})

	// Возраст.
	if months := rdapAge(host); months == nil {
		r.Checks = append(r.Checks, checkPart{Name: "Возраст", Got: 5, Max: 15, Note: "возраст узнать не вышло — считаем с опаской"})
	} else if *months >= 24 {
		r.Checks = append(r.Checks, checkPart{Name: "Возраст", Got: 15, Max: 15, Note: fmt.Sprintf("домену ~%d г. — старый, это плюс", *months/12)})
	} else if *months >= 12 {
		r.Checks = append(r.Checks, checkPart{Name: "Возраст", Got: 10, Max: 15, Note: fmt.Sprintf("домену ~%d мес. — средний", *months)})
	} else {
		r.Checks = append(r.Checks, checkPart{Name: "Возраст", Got: 3, Max: 15, Note: fmt.Sprintf("домену ~%d мес. — молодой, Pinterest строже", *months)})
	}

	// Штрафы.
	penalty := 0
	low := strings.ToLower(host)
	caps := []int{}
	if hasSuffixAny(low, shorteners) {
		penalty += 10
		caps = append(caps, 39)
		r.Notes = append(r.Notes, "Это сокращалка ссылок — Pinterest их блочит почти всегда.")
	}
	if hasSuffixAny(low, freeHosts) {
		penalty += 15
		caps = append(caps, 79)
		r.Notes = append(r.Notes, "Бесплатный хостинг: выше жёлтого не поднимем. Для посадки лучше свой домен — там репутация только твоя.")
	}
	if strings.Contains(low, "sites.google") {
		penalty += 10
		r.Notes = append(r.Notes, "Google Sites уже замечен в массовых блоках — показы режутся.")
	}
	if hasAny(strings.ToLower(finalURL), affMarks) {
		penalty += 5
		r.Notes = append(r.Notes, "В адресе партнёрский хвост — лучше чистая ссылка без меток.")
	}
	if hasJsRedirect(f.body) != "" {
		penalty += 10
		r.Notes = append(r.Notes, "На странице переброс через скрипт — Pinterest считает это маскировкой.")
	}
	// Взгляд бота: Pinterest смотрит глазами своего краулера.
	// Если боту показывают другое место, чем человеку, — это маскировка, за неё банят.
	if len(f.hops) > 0 {
		bot := fetchChain(start, uaBot)
		if len(bot.hops) > 0 {
			botFinal := hostOf(bot.hops[len(bot.hops)-1].url)
			mobFinal := hostOf(finalURL)
			botStatus := bot.hops[len(bot.hops)-1].status
			mobStatus := f.hops[len(f.hops)-1].status
			switch {
			case !sameSite(botFinal, mobFinal):
				penalty += 10
				caps = append(caps, 39)
				r.Notes = append(r.Notes, "Глазами бота уводит на другой домен, чем человеку — похоже на маскировку, за это банят.")
			case mobStatus < 400 && botStatus >= 400:
				penalty += 5
				r.Notes = append(r.Notes, "Человеку страница открывается, а боту — нет. Pinterest смотрит глазами бота.")
			}
		}
	}
	// Внешний вердикт Google. Нужен бесплатный ключ в файле gsb.key рядом с кнопками.
	gsbHit := gsbListed(finalURL)
	if gsbHit {
		penalty += 15
		r.Notes = append(r.Notes, "Google считает ссылку опасной — Pinterest такие режет почти наверняка.")
	}
	if loadGSBKey() == "" {
		r.Info = append(r.Info, "Google: не проверено — рекомендуется ключ (страховка от худшего случая, как получить — в README.md)")
	} else if gsbHit {
		r.Info = append(r.Info, "Google: в чёрном списке")
	} else {
		r.Info = append(r.Info, "Google: чисто")
	}
	// Чёрные списки спама: три штуки сразу, чтобы было дольше, зато честно.
	type listHit struct {
		name string
		hit  bool
	}
	listCh := make(chan listHit, 3)
	go func() {
		hit, refused := dblListed(host)
		if refused {
			r.Info = append(r.Info, "Spamhaus: спросить не вышло")
		}
		listCh <- listHit{"Spamhaus DBL", hit}
	}()
	go func() { listCh <- listHit{"SURBL", surblListed(host)} }()
	go func() { listCh <- listHit{"URLhaus", urlhausListed(finalURL)} }()
	badLists := []string{}
	for i := 0; i < 3; i++ {
		if h := <-listCh; h.hit {
			badLists = append(badLists, h.name)
		}
	}
	if len(badLists) > 0 {
		penalty += 15
		r.Notes = append(r.Notes, "Домен в чёрных списках спама: "+strings.Join(badLists, ", ")+". Pinterest такое режет.")
		r.Info = append(r.Info, "Списки спама: найден в "+strings.Join(badLists, ", "))
	} else {
		r.Info = append(r.Info, "Списки спама: чисто (Spamhaus, SURBL, URLhaus)")
	}
	// Страницы доверия: контакты, политика. Их отсутствие Pinterest не любит.
	if len(f.hops) > 0 && f.hops[len(f.hops)-1].status == 200 && len(f.body) > 500 {
		if len(reTrust.FindAllString(f.body, -1)) < 2 {
			penalty += 5
			r.Notes = append(r.Notes, "Не видно страниц доверия (контакты, политика). Добавь их — Pinterest любит живые сайты.")
		}
	}
	if penalty > maxPenalty {
		penalty = maxPenalty
	}
	cleanGot := cleanMax - penalty
	if cleanGot < 0 {
		cleanGot = 0
	}
	extra := penalty - cleanMax
	if extra < 0 {
		extra = 0
	}
	if penalty > 0 {
		r.Checks = append(r.Checks, checkPart{Name: "Без хвостов", Got: cleanGot, Max: cleanMax, Note: fmt.Sprintf("штраф %d", penalty)})
	} else {
		r.Checks = append(r.Checks, checkPart{Name: "Без хвостов", Got: cleanGot, Max: cleanMax, Note: "хвостов и перебросов не видно"})
	}

	sum := 0
	for _, p := range r.Checks {
		sum += p.Got
	}
	score := sum - extra
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	// Google внёс в чёрный список — выше оранжевого не поднимем, как бы всё остальное ни блестело.
	if gsbHit {
		caps = append(caps, 35)
	}
	for _, c := range caps {
		if score > c {
			score = c
		}
	}
	r.Score = score
	r.Verdict, r.Word = verdictOf(score)
	r.Important = "Это НЕ внутренняя цифра Pinterest. Это наш индекс по открытым сигналам."
	r.OK = true
	return r
}

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

// Спрашивает у Google, считает ли он ссылку опасной.
func gsbListed(pageURL string) bool {
	key := loadGSBKey()
	if key == "" {
		return false
	}
	payload := map[string]any{
		"client": map[string]any{"clientId": "pinterest-trust-check", "clientVersion": "1.0"},
		"threatInfo": map[string]any{
			"threatTypes":      []string{"MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"},
			"platformTypes":    []string{"ANY_PLATFORM"},
			"threatEntryTypes": []string{"URL"},
			"threatEntries":    []any{map[string]any{"url": pageURL}},
		},
	}
	data, _ := json.Marshal(payload)
	client := &http.Client{Timeout: timeoutMs * time.Millisecond}
	req, err := http.NewRequest("POST", "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+url.QueryEscape(key), strings.NewReader(string(data)))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil {
		return false
	}
	var out struct {
		Matches []any `json:"matches"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false
	}
	return len(out.Matches) > 0
}

// Короткая запись баллов по пунктам, чтобы ловить скачки: R30 T25 S10 H1 A8 C15.
func compactChecks(parts []checkPart) string {
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

// Дописывает итог в историю. Файл не растёт бесконечно — держим хвост.
func appendHistory(dir string, r result) {
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
		clean(r.FinalURL), compactChecks(r.Checks), clean(strings.Join(r.Notes, " | ")))
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

// Хостинг по адресу через открытый справочник (без ключа). Только справка, не балл.
func hostingInfo(ipStr string) string {
	ip := net.ParseIP(ipStr)
	v4 := ip.To4()
	if v4 == nil {
		return "Хостинг: по адресу " + ipStr
	}
	q := fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", v4[3], v4[2], v4[1], v4[0])
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	txts, err := net.DefaultResolver.LookupTXT(ctx, q)
	if err != nil || len(txts) == 0 {
		return "Хостинг: узнать не вышло (адрес " + ipStr + ")"
	}
	parts := strings.Split(txts[0], "|")
	for i := range parts {
		parts[i] = strings.TrimSpace(parts[i])
	}
	if len(parts) >= 3 {
		return fmt.Sprintf("Хостинг: сеть AS%s, страна %s (адрес %s)", parts[0], parts[2], ipStr)
	}
	return "Хостинг: " + strings.TrimSpace(txts[0])
}

// Чёрный список Spamhaus через DNS (для личного пользования бесплатно).
// Возвращает: найден, причина-отказа-запроса.
func dblListed(host string) (bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host+".dbl.spamhaus.org")
	if err != nil || len(addrs) == 0 {
		return false, false
	}
	for _, a := range addrs {
		s := a.IP.String()
		if strings.HasPrefix(s, "127.0.1.") {
			return true, false
		}
		if s == "127.255.255.254" {
			return false, true
		}
	}
	return false, false
}

// Чёрный список SURBL через DNS (для личного пользования бесплатно).
func surblListed(host string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host+".multi.surbl.org")
	return err == nil && len(addrs) > 0
}

// Чёрный список URLhaus (без ключа, бесплатно).
func urlhausListed(pageURL string) bool {
	payload := map[string]any{"url": pageURL}
	data, _ := json.Marshal(payload)
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("POST", "https://urlhaus-api.abuse.ch/v1/url/", strings.NewReader(string(data)))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return false
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil {
		return false
	}
	var out struct {
		Status string `json:"query_status"`
		Threat string `json:"threat"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return false
	}
	return out.Status == "ok" && out.Threat != ""
}

// Следы страниц доверия: контакты, политика, о себе. Их любит Pinterest.
var reTrust = regexp.MustCompile(`(?i)(privacy|confiden|policy|terms|contact|kontakt|about|imprint|оферт|конфиденц|контакт|связ[а-я]ться)`)

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

func printOne(r result) {
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
		fmt.Println("\nНа что обратить внимание:")
		for _, n := range r.Notes {
			fmt.Printf("  ! %s\n", n)
		}
	}
	if len(r.Info) > 0 {
		fmt.Println("\nСправочно:")
		for _, s := range r.Info {
			fmt.Printf("  • %s\n", s)
		}
	}
}

func printTable(list []result) {
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
func writeCSV(dir string, list []result) string {
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

func main() {
	args := os.Args[1:]
	wantJSON := false
	links := []string{}
	for _, a := range args {
		if a == "--json" {
			wantJSON = true
			continue
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
		fmt.Println("  • Создай черновик пина с этой ссылкой. Если Pinterest пишет про спам — домен в блоке.")
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
	results := make([]result, 0, len(list))
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

// Интерфейс в браузере: только этот компьютер, наружу ничего не торчит.
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
	url := "http://" + serveAddr + "/"
	fmt.Println("Открываю страницу " + url)
	fmt.Println("Закрой это окно, чтобы остановить.")
	_ = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	if err := http.ListenAndServe(serveAddr, mux); err != nil {
		fmt.Println("Не запустилось:", err)
		fmt.Println("Возможно, уже открыта вторая копия — закрой её.")
	}
}
