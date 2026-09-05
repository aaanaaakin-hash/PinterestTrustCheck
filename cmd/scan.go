// Сетевые сигналы: всё, что ходит наружу. Чистая логика — в internal/check.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"trustcheck/internal/check"
)

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
)

// Точки подмены для тестов: в обычной работе указывают на настоящие функции.
var (
	resolveFn     = resolveGuard
	tlsFn         = func(host string) tlsOut { return tlsInfo(host+":443", host) }
	ageFn         = rdapAge
	gsbFn         = gsbListed
	hostingFn     = hostingInfo
	listsFn       = listsOf
	waybackFn     = waybackFirst
	crtFn         = crtFirst
	otxFn         = otxPulses
	vtFn          = vtStats
	newScanClient = func() *http.Client {
		return &http.Client{
			Timeout: timeoutMs * time.Millisecond,
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
	}
	// Только для тестов: не проверять подпись сертификата.
	tlsSkipVerify = false
)

// Домен должен находиться и вести наружу (защита от подмены).
// Возвращает первый внешний адрес — он нужен для справки о хостинге.
func resolveGuard(host string) (string, error) {
	if ip := net.ParseIP(host); ip != nil {
		if check.IsPrivateIP(ip) {
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
		if !check.IsPrivateIP(a.IP) {
			return a.IP.String(), nil
		}
	}
	return "", fmt.Errorf("ведёт внутрь")
}

type hopOut struct {
	url    string
	status int
}

type fetchOut struct {
	hops    []hopOut
	headers http.Header
	body    string
	ms      int64
	stopped bool
	guarded bool
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
	client := newScanClient()
	out := fetchOut{}
	cur := start
	for i := 0; i <= maxRedirects; i++ {
		st, hdr, loc, body, ms, err := fetchOnce(client, cur, ua)
		if err != nil {
			return out
		}
		out.hops = append(out.hops, hopOut{url: cur, status: st})
		out.ms += ms
		out.headers = hdr
		out.body = body
		if (st == 301 || st == 302 || st == 303 || st == 307 || st == 308) && loc != "" {
			next, err := url.Parse(loc)
			if err != nil {
				return out
			}
			base, _ := url.Parse(cur)
			target := base.ResolveReference(next).String()
			// Переброс на другой хост проверяем: внутрь закрытой сети не ходим.
			if check.HostOf(target) != check.HostOf(cur) && hostIsPrivate(check.HostOf(target)) {
				out.guarded = true
				return out
			}
			cur = target
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

func tlsInfo(addr, server string) tlsOut {
	dialer := &net.Dialer{Timeout: timeoutMs * time.Millisecond}
	conn, err := tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{ServerName: server, InsecureSkipVerify: tlsSkipVerify})
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
// Для .com/.net есть запасной справочник, если общий молчит.
func rdapAge(host string) *int {
	urls := []string{"https://rdap.org/domain/" + url.PathEscape(host)}
	if strings.HasSuffix(host, ".com") || strings.HasSuffix(host, ".net") {
		urls = append(urls, "https://rdap.verisign.com/com/v1/domain/"+url.PathEscape(host))
	}
	for _, u := range urls {
		if m := rdapMonths(u); m != nil {
			return m
		}
	}
	return nil
}

func rdapMonths(u string) *int {
	client := &http.Client{Timeout: timeoutMs * time.Millisecond}
	req, _ := http.NewRequest("GET", u, nil)
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

// Хост ведёт внутрь закрытой сети? Чужой сайт мог подсунуть такой переброс.
func hostIsPrivate(host string) bool {
	if ip := net.ParseIP(host); ip != nil {
		return check.IsPrivateIP(ip)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(addrs) == 0 {
		return true
	}
	for _, a := range addrs {
		if !check.IsPrivateIP(a.IP) {
			return false
		}
	}
	return true
}

// Общий запрос к Google. Возвращает код ответа и есть ли совпадение.
func gsbQuery(key, pageURL string) (int, bool) {
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
		return 0, false
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0, false
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil {
		return res.StatusCode, false
	}
	var out struct {
		Matches []any `json:"matches"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return res.StatusCode, false
	}
	return res.StatusCode, len(out.Matches) > 0
}

// Проверка чужих ключей безвредными запросами. Пусто — ключ рабочий.
func validateOTXKey(key string) string {
	// Общая сводка отдаётся даже без ключа, поэтому проверяем подписками — там без ключа никак.
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=1", nil)
	req.Header.Set("X-OTX-API-KEY", key)
	res, err := client.Do(req)
	if err != nil {
		return "не вышло связаться — попробуй позже"
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case 200:
		return ""
	case 401, 403:
		return "сервис ключ отклонил — проверь, что скопировал целиком"
	default:
		return "сервис ответил ошибкой — попробуй позже"
	}
}

func validateVTKey(key string) string {
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://www.virustotal.com/api/v3/domains/example.com", nil)
	req.Header.Set("x-apikey", key)
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return "не вышло связаться — попробуй позже"
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case 200, 404:
		return ""
	case 401, 403:
		return "сервис ключ отклонил — проверь, что скопировал целиком"
	case 429:
		return "лимит исчерпан — попробуй позже"
	default:
		return "сервис ответил ошибкой — попробуй позже"
	}
}

// Проверка ключа через безвредный адрес. Пусто — ключ рабочий.
func validateGSBKey(key string) string {
	status, _ := gsbQuery(key, "https://example.com/")
	switch {
	case status == 0:
		return "не вышло связаться с Google, попробуй позже"
	case status == 400 || status == 401 || status == 403:
		return "Google ключ отклонил — проверь, что скопировал целиком"
	case status != 200:
		return "Google ответил ошибкой — попробуй позже"
	default:
		return ""
	}
}

// Спрашивает у Google, считает ли он ссылку опасной.
func gsbListed(pageURL string) bool {
	key := loadGSBKey()
	if key == "" {
		return false
	}
	status, listed := gsbQuery(key, pageURL)
	return status == 200 && listed
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

// Следы страниц доверия: контакты, политика. Их любит Pinterest.
var reTrust = regexp.MustCompile(`(?i)(privacy|confiden|policy|terms|contact|kontakt|about|imprint|оферт|конфиденц|контакт|связаться)`)

// Разбор ответа URIBL: биты 2/4/8 — списки, 1 — отказ в обслуживании.
func parseURIBL(ip string) (hit, refused bool) {
	switch ip {
	case "127.0.0.2", "127.0.0.4", "127.0.0.8", "127.0.0.14":
		return true, false
	case "127.0.0.1", "127.0.0.255":
		return false, true
	default:
		return false, false
	}
}

// Чёрный список URIBL через DNS (для личного пользования бесплатно).
func uriblListed(host string) (bool, bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host+".multi.uribl.com")
	if err != nil || len(addrs) == 0 {
		return false, false
	}
	hit, refused := false, false
	for _, a := range addrs {
		if h, r := parseURIBL(a.IP.String()); h {
			hit = true
		} else if r {
			refused = true
		}
	}
	return hit, refused && !hit
}

// Проверка по четырём чёрным спискам сразу. Возвращает имена сработавших и был ли отказ.
func listsOf(host, finalURL string) (bad []string, refused bool) {
	type listHit struct {
		name string
		hit  bool
	}
	listCh := make(chan listHit, 4)
	go func() {
		hit, no := dblListed(host)
		if no {
			refused = true
		}
		listCh <- listHit{"Spamhaus DBL", hit}
	}()
	go func() { listCh <- listHit{"SURBL", surblListed(host)} }()
	go func() { listCh <- listHit{"URLhaus", urlhausListed(finalURL)} }()
	go func() {
		hit, no := uriblListed(host)
		if no {
			refused = true
		}
		listCh <- listHit{"URIBL", hit}
	}()
	for i := 0; i < 4; i++ {
		if h := <-listCh; h.hit {
			bad = append(bad, h.name)
		}
	}
	return bad, refused
}

// Прошлое домена в веб-архиве: первый снимок и сколько их.
type archiveInfo struct {
	first  string
	months int
	total  int
	ok     bool
}

func waybackFirst(host string) archiveInfo {
	// Без фильтров на их стороне и маленькими порциями: архив отвечает медленно.
	u := "https://web.archive.org/cdx/search/cdx?url=" + url.QueryEscape(host) +
		"&output=json&fl=timestamp,original&limit=5"
	client := &http.Client{Timeout: 25 * time.Second}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", uaBrowser)
	res, err := client.Do(req)
	if err != nil {
		return archiveInfo{}
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 500000))
	if err != nil {
		return archiveInfo{}
	}
	var rows [][]string
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) == 0 {
		return archiveInfo{}
	}
	best := ""
	total := 0
	for _, row := range rows {
		if len(row) == 0 || len(row[0]) != 14 || row[0] == "timestamp" {
			continue
		}
		total++
		if best == "" || row[0] < best {
			best = row[0]
		}
	}
	if best == "" {
		return archiveInfo{}
	}
	t, err := time.Parse("20060102150405", best)
	if err != nil {
		return archiveInfo{}
	}
	m := int(time.Since(t).Hours() / 730)
	return archiveInfo{first: t.Format("2006-01-02"), months: m, total: total, ok: true}
}

// История сертификатов: первый и сколько их.
type certInfo struct {
	first  string
	months int
	count  int
	ok     bool
}

func crtFirst(host string) certInfo {
	// Сначала точное имя (ответ маленький), потом все поддомены.
	if ci := crtQuery("https://crt.sh/?q=" + url.QueryEscape(host) + "&output=json"); ci.ok {
		return ci
	}
	return crtQuery("https://crt.sh/?q=%25." + url.QueryEscape(host) + "&output=json")
}

func crtQuery(u string) certInfo {
	client := &http.Client{Timeout: 15 * time.Second}
	req, _ := http.NewRequest("GET", u, nil)
	req.Header.Set("User-Agent", uaBrowser)
	res, err := client.Do(req)
	if err != nil {
		return certInfo{}
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, 5000000))
	if err != nil {
		return certInfo{}
	}
	var rows []struct {
		NotBefore string `json:"not_before"`
	}
	if err := json.Unmarshal(raw, &rows); err != nil || len(rows) == 0 {
		return certInfo{}
	}
	best := ""
	for _, row := range rows {
		d := row.NotBefore
		if len(d) < 10 {
			continue
		}
		if best == "" || d < best {
			best = d
		}
	}
	if best == "" {
		return certInfo{}
	}
	t, err := time.Parse("2006-01-02T15:04:05", best[:19])
	if err != nil {
		return certInfo{}
	}
	return certInfo{first: t.Format("2006-01-02"), months: int(time.Since(t).Hours() / 730), count: len(rows), ok: true}
}

// Жалобы на домен в OTX. Статус: ok, no-key, bad-key, fail.
func otxPulses(host string) (int, string) {
	key := loadOTXKey()
	if key == "" {
		return 0, "no-key"
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://otx.alienvault.com/api/v1/indicators/domain/"+url.PathEscape(host)+"/general", nil)
	req.Header.Set("X-OTX-API-KEY", key)
	res, err := client.Do(req)
	if err != nil {
		return 0, "fail"
	}
	defer res.Body.Close()
	if res.StatusCode == 401 || res.StatusCode == 403 {
		return 0, "bad-key"
	}
	if res.StatusCode == 404 {
		return 0, "ok"
	}
	if res.StatusCode != 200 {
		return 0, "fail"
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 200000))
	if err != nil {
		return 0, "fail"
	}
	var doc struct {
		PulseInfo struct {
			Count int `json:"count"`
		} `json:"pulse_info"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, "fail"
	}
	return doc.PulseInfo.Count, "ok"
}

// Вердикт VirusTotal по домену. Статус: ok, no-key, bad-key, limited, fail.
func vtStats(host string) (malicious, suspicious, total int, status string) {
	key := loadVTKey()
	if key == "" {
		return 0, 0, 0, "no-key"
	}
	client := &http.Client{Timeout: 10 * time.Second}
	req, _ := http.NewRequest("GET", "https://www.virustotal.com/api/v3/domains/"+url.PathEscape(host), nil)
	req.Header.Set("x-apikey", key)
	req.Header.Set("Accept", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return 0, 0, 0, "fail"
	}
	defer res.Body.Close()
	switch res.StatusCode {
	case 401, 403:
		return 0, 0, 0, "bad-key"
	case 404:
		return 0, 0, 0, "unknown"
	case 429:
		return 0, 0, 0, "limited"
	}
	if res.StatusCode != 200 {
		return 0, 0, 0, "fail"
	}
	raw, err := io.ReadAll(io.LimitReader(res.Body, 300000))
	if err != nil {
		return 0, 0, 0, "fail"
	}
	var doc struct {
		Data struct {
			Attributes struct {
				Stats struct {
					Malicious  int `json:"malicious"`
					Suspicious int `json:"suspicious"`
					Harmless   int `json:"harmless"`
					Undetected int `json:"undetected"`
				} `json:"last_analysis_stats"`
			} `json:"attributes"`
		} `json:"data"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return 0, 0, 0, "fail"
	}
	s := doc.Data.Attributes.Stats
	return s.Malicious, s.Suspicious, s.Malicious + s.Suspicious + s.Harmless + s.Undetected, "ok"
}

// Полная проверка одной ссылки.
func checkOne(link string) check.Result {
	r := check.Result{Link: link, Notes: []string{}, Checks: []check.CheckPart{}, Hops: []string{}}
	host, start, err := check.ToStartURL(link)
	if err != nil {
		r.Error = "Проверь написание ссылки"
		return r
	}
	r.Host = host

	if ip, err := resolveFn(host); err != nil {
		r.Host = host
		r.Error = "Домен не находится, проверять нечего"
		return r
	} else {
		r.Info = append(r.Info, hostingFn(ip))
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
		r.Checks = append(r.Checks, check.CheckPart{Name: "Редиректы", Got: 0, Max: 30, Note: "сайт не открылся за 10 секунд"})
		r.Notes = append(r.Notes, "Сайт не отвечает. Pinterest тоже сочтёт его небезопасным.")
	} else {
		count := len(f.hops) - 1
		hopHosts := []string{}
		for _, h := range f.hops {
			hopHosts = append(hopHosts, check.HostOf(h.url))
		}
		cross := false
		for _, h := range hopHosts {
			if !check.SameSite(h, hopHosts[0]) {
				cross = true
			}
		}
		switch {
		case f.guarded:
			r.Checks = append(r.Checks, check.CheckPart{Name: "Редиректы", Got: 0, Max: 30, Note: "переброс ведёт внутрь закрытой сети — дальше не пошли (защита)"})
		case f.stopped:
			r.Checks = append(r.Checks, check.CheckPart{Name: "Редиректы", Got: 0, Max: 30, Note: fmt.Sprintf("больше %d прыжков — Pinterest такое режет", maxRedirects)})
		case count == 0:
			r.Checks = append(r.Checks, check.CheckPart{Name: "Редиректы", Got: 30, Max: 30, Note: "прямой адрес без прыжков — идеально"})
		case count == 1 && !cross:
			r.Checks = append(r.Checks, check.CheckPart{Name: "Редиректы", Got: 25, Max: 30, Note: "один прыжок внутри своего сайта — нормально"})
		case count == 1:
			r.Checks = append(r.Checks, check.CheckPart{Name: "Редиректы", Got: 14, Max: 30, Note: "один прыжок на другой домен — лучше прямую ссылку"})
		case count == 2:
			r.Checks = append(r.Checks, check.CheckPart{Name: "Редиректы", Got: 8, Max: 30, Note: "два прыжка — уже риск просадки"})
		default:
			r.Checks = append(r.Checks, check.CheckPart{Name: "Редиректы", Got: 0, Max: 30, Note: fmt.Sprintf("%d прыжка — Pinterest такое обычно режет", count)})
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
	finalHost := check.HostOf(finalURL)
	if finalHost == "" {
		finalHost = host
	}
	t := tlsFn(finalHost)
	switch {
	case t.ok && (t.protocol == "TLSv1.3" || t.protocol == "TLSv1.2") && t.daysLeft > 30:
		r.Checks = append(r.Checks, check.CheckPart{Name: "Шифрование", Got: 25, Max: 25, Note: "сертификат в порядке (" + t.protocol + ")"})
	case t.ok && t.daysLeft > 0:
		r.Checks = append(r.Checks, check.CheckPart{Name: "Шифрование", Got: 12, Max: 25, Note: "сертификат есть, но слабый или скоро кончится"})
		r.Notes = append(r.Notes, "Проверь срок сертификата, скоро кончится.")
	default:
		r.Checks = append(r.Checks, check.CheckPart{Name: "Шифрование", Got: 0, Max: 25, Note: "сертификат битый или его нет — Pinterest блочит"})
	}

	// Скорость.
	switch {
	case f.ms < 600:
		r.Checks = append(r.Checks, check.CheckPart{Name: "Скорость", Got: 10, Max: 10, Note: fmt.Sprintf("отвечает за %d мс — быстро", f.ms)})
	case f.ms < 1500:
		r.Checks = append(r.Checks, check.CheckPart{Name: "Скорость", Got: 6, Max: 10, Note: fmt.Sprintf("отвечает за %d мс — средне", f.ms)})
	default:
		r.Checks = append(r.Checks, check.CheckPart{Name: "Скорость", Got: 2, Max: 10, Note: fmt.Sprintf("отвечает за %d мс — медленно, Pinterest не любит", f.ms)})
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
	r.Checks = append(r.Checks, check.CheckPart{Name: "Заголовки", Got: hg, Max: 5, Note: hnote})

	// Возраст. Молодым доменам режем потолок: зелёный надо заслужить годами.
	ageCap := -1
	ageMonths := ageFn(host)
	if months := ageMonths; months == nil {
		r.Checks = append(r.Checks, check.CheckPart{Name: "Возраст", Got: 5, Max: 15, Note: "возраст узнать не вышло — считаем с опаской"})
	} else if *months >= 24 {
		r.Checks = append(r.Checks, check.CheckPart{Name: "Возраст", Got: 15, Max: 15, Note: fmt.Sprintf("домену ~%d г. — старый, это плюс", *months/12)})
	} else if *months >= 12 {
		r.Checks = append(r.Checks, check.CheckPart{Name: "Возраст", Got: 10, Max: 15, Note: fmt.Sprintf("домену ~%d мес. — средний", *months)})
	} else if *months >= 6 {
		r.Checks = append(r.Checks, check.CheckPart{Name: "Возраст", Got: 5, Max: 15, Note: fmt.Sprintf("домену ~%d мес. — молодой, выше жёлтого не поднимем", *months)})
		ageCap = 79
	} else {
		r.Checks = append(r.Checks, check.CheckPart{Name: "Возраст", Got: 3, Max: 15, Note: fmt.Sprintf("домену ~%d мес. — совсем молодой, выше оранжевого не поднимем", *months)})
		ageCap = 59
	}

	// Штрафы.
	penalty := 0
	caps := []int{}
	low := strings.ToLower(host)
	if check.HasSuffixAny(low, shorteners) {
		penalty += 10
		caps = append(caps, 39)
		r.Notes = append(r.Notes, "Это сокращалка ссылок — Pinterest их блочит почти всегда.")
	}
	if check.HasSuffixAny(low, freeHosts) {
		penalty += 15
		caps = append(caps, 79)
		r.Notes = append(r.Notes, "Бесплатный хостинг: выше жёлтого не поднимем. Для посадки лучше свой домен — там репутация только твоя.")
	}
	if strings.Contains(low, "sites.google") {
		penalty += 10
		r.Notes = append(r.Notes, "Google Sites уже замечен в массовых блоках — показы режутся.")
	}
	if check.HasAny(strings.ToLower(finalURL), affMarks) {
		penalty += 5
		r.Notes = append(r.Notes, "В адресе партнёрский хвост — лучше чистая ссылка без меток.")
	}
	if check.HasJsRedirect(f.body) != "" {
		penalty += 10
		r.Notes = append(r.Notes, "На странице переброс через скрипт — Pinterest считает это маскировкой.")
	}
	// Взгляд бота: Pinterest смотрит глазами своего краулера.
	if len(f.hops) > 0 {
		bot := fetchChain(start, uaBot)
		if len(bot.hops) > 0 {
			botFinal := check.HostOf(bot.hops[len(bot.hops)-1].url)
			mobFinal := check.HostOf(finalURL)
			botStatus := bot.hops[len(bot.hops)-1].status
			mobStatus := f.hops[len(f.hops)-1].status
			switch {
			case !check.SameSite(botFinal, mobFinal):
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
	gsbHit := gsbFn(finalURL)
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
	badLists, listsRefused := listsFn(host, finalURL)
	if listsRefused {
		r.Info = append(r.Info, "Spamhaus: спросить не вышло")
	}
	if len(badLists) > 0 {
		penalty += 15
		r.Notes = append(r.Notes, "Домен в чёрных списках спама: "+strings.Join(badLists, ", ")+". Pinterest такое режет.")
		r.Info = append(r.Info, "Списки спама: найден в "+strings.Join(badLists, ", "))
	} else {
		r.Info = append(r.Info, "Списки спама: чисто (Spamhaus, SURBL, URLhaus, URIBL)")
	}
	// Прошлое домена: архив, сертификаты, жалобы, вердикты. Спрашиваем разом.
	type repOut struct {
		wb       archiveInfo
		ci       certInfo
		otxN     int
		otxSt    string
		vtM      int
		vtS      int
		vtTot    int
		vtSt     string
	}
	repCh := make(chan repOut, 1)
	go func() {
		var o repOut
		done := make(chan struct{}, 4)
		go func() { o.wb = waybackFn(host); done <- struct{}{} }()
		go func() { o.ci = crtFn(host); done <- struct{}{} }()
		go func() { o.otxN, o.otxSt = otxFn(host); done <- struct{}{} }()
		go func() { o.vtM, o.vtS, o.vtTot, o.vtSt = vtFn(host); done <- struct{}{} }()
		for i := 0; i < 4; i++ {
			<-done
		}
		repCh <- o
	}()
	rep := <-repCh
	if rep.wb.ok {
		r.Info = append(r.Info, fmt.Sprintf("Архив: первый снимок %s", rep.wb.first))
		// Паспорт говорит «старый», а в архиве его почти нет — похоже, перекупался.
		if ageMonths != nil && *ageMonths >= 24 && rep.wb.months < 12 {
			penalty += 10
			caps = append(caps, 59)
			r.Notes = append(r.Notes, fmt.Sprintf("Паспорт говорит, что домену ~%d г., а в архиве он виден меньше года — похоже, домен перекупался. Такие Pinterest не любит.", *ageMonths/12))
		}
	} else {
		r.Info = append(r.Info, "Архив: снимков не нашли")
	}
	if rep.ci.ok {
		r.Info = append(r.Info, fmt.Sprintf("Сертификаты: первый %s (всего %d)", rep.ci.first, rep.ci.count))
	} else {
		r.Info = append(r.Info, "Сертификаты: историю глянуть не вышло")
	}
	switch rep.otxSt {
	case "no-key":
		r.Info = append(r.Info, "OTX: нет ключа (otx.key) — жалобы не проверены")
	case "bad-key":
		r.Info = append(r.Info, "OTX: ключ не подошёл")
	case "fail":
		r.Info = append(r.Info, "OTX: спросить не вышло")
	default:
		if rep.otxN > 0 {
			penalty += 10
			r.Notes = append(r.Notes, fmt.Sprintf("На домен %d жалоб в базе OTX — его уже светили в угрозах.", rep.otxN))
			r.Info = append(r.Info, fmt.Sprintf("OTX: жалоб %d", rep.otxN))
			if rep.otxN >= 5 {
				caps = append(caps, 59)
			}
		} else {
			r.Info = append(r.Info, "OTX: жалоб нет")
		}
	}
	switch rep.vtSt {
	case "no-key":
		r.Info = append(r.Info, "VirusTotal: нет ключа (vt.key) — вердикты не проверены")
	case "bad-key":
		r.Info = append(r.Info, "VirusTotal: ключ не подошёл")
	case "limited":
		r.Info = append(r.Info, "VirusTotal: лимит исчерпан, пропускаем")
	case "unknown":
		r.Info = append(r.Info, "VirusTotal: домен им неизвестен")
	case "fail":
		r.Info = append(r.Info, "VirusTotal: спросить не вышло")
	default:
		if rep.vtM > 0 {
			penalty += 15
			caps = append(caps, 35)
			r.Notes = append(r.Notes, fmt.Sprintf("VirusTotal: %d движков считают домен вредоносным.", rep.vtM))
			r.Info = append(r.Info, fmt.Sprintf("VirusTotal: вредоносный (%d движков)", rep.vtM))
		} else if rep.vtS > 0 {
			penalty += 8
			r.Notes = append(r.Notes, fmt.Sprintf("VirusTotal: %d движков считают домен подозрительным.", rep.vtS))
			r.Info = append(r.Info, fmt.Sprintf("VirusTotal: подозрительный (%d движков)", rep.vtS))
		} else {
			r.Info = append(r.Info, fmt.Sprintf("VirusTotal: чисто (движков: %d)", rep.vtTot))
		}
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
		r.Checks = append(r.Checks, check.CheckPart{Name: "Без хвостов", Got: cleanGot, Max: cleanMax, Note: fmt.Sprintf("штраф %d", penalty)})
	} else {
		r.Checks = append(r.Checks, check.CheckPart{Name: "Без хвостов", Got: cleanGot, Max: cleanMax, Note: "хвостов и перебросов не видно"})
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
	if ageCap >= 0 {
		caps = append(caps, ageCap)
	}
	for _, c := range caps {
		if score > c {
			score = c
		}
	}
	r.Score = score
	r.Verdict, r.Word = check.VerdictOf(score)
	r.Important = "Это НЕ внутренняя цифра Pinterest. Это наш индекс по открытым сигналам."
	r.OK = true
	return r
}
