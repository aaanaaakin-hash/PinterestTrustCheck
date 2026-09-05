// Тесты сетевого слоя на подменном сервере (без настоящего интернета).
// Подменяем только справочники (возраст, списки, Google), а запросы идут
// по-настоящему — в местный тестовый сервер.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var errTestDNS = errors.New("нет сети")

// Глушим внешние справочники, сеть остаётся настоящей (местной).
func stubEnv(t *testing.T) {
	t.Helper()
	oldResolve, oldAge, oldGSB, oldLists, oldHosting, oldTLS, oldSkip, oldClient :=
		resolveFn, ageFn, gsbFn, listsFn, hostingFn, tlsFn, tlsSkipVerify, newScanClient
	oldWayback, oldCrt, oldOtx, oldVt := waybackFn, crtFn, otxFn, vtFn
	t.Cleanup(func() {
		resolveFn, ageFn, gsbFn, listsFn, hostingFn, tlsFn, tlsSkipVerify, newScanClient =
			oldResolve, oldAge, oldGSB, oldLists, oldHosting, oldTLS, oldSkip, oldClient
		waybackFn, crtFn, otxFn, vtFn = oldWayback, oldCrt, oldOtx, oldVt
	})
	m30 := 30
	resolveFn = func(string) (string, error) { return "127.0.0.1", nil }
	ageFn = func(string) *int { return &m30 }
	gsbFn = func(string) bool { return false }
	listsFn = func(string, string) ([]string, bool) { return nil, false }
	hostingFn = func(string) string { return "тест" }
	tlsFn = func(string) tlsOut { return tlsOut{ok: true, protocol: "TLSv1.3", daysLeft: 400} }
	waybackFn = func(string) archiveInfo { return archiveInfo{} }
	crtFn = func(string) certInfo { return certInfo{} }
	otxFn = func(string) (int, string) { return 0, "no-key" }
	vtFn = func(string) (int, int, int, string) { return 0, 0, 0, "no-key" }
	tlsSkipVerify = true
}

// Клиент, который любое имя ведёт на местный тестовый сервер.
func testClient(port string) *http.Client {
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, "127.0.0.1:"+port)
		},
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeoutMs * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func testPort(ts *httptest.Server) string {
	addr := ts.Listener.Addr().String()
	return addr[strings.LastIndex(addr, ":")+1:]
}

const goodPage = `<html><head><title>t</title></head><body><p>privacy policy contact about us privacy contact</p></body></html>`

func TestCheckOneClean(t *testing.T) {
	stubEnv(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.WriteHeader(200)
		_, _ = w.Write([]byte(goodPage))
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/")
	if r.Error != "" {
		t.Fatalf("неожиданная ошибка: %s", r.Error)
	}
	if len(r.Checks) < 1 || r.Checks[0].Name != "Редиректы" || r.Checks[0].Got != 30 {
		t.Errorf("редиректы: %+v", r.Checks)
	}
	if r.Score < 80 {
		t.Errorf("чистая страница: балл %d, ждали 80+", r.Score)
	}
	if len(r.Hops) != 1 {
		t.Errorf("прыжков %d, ждали 1", len(r.Hops))
	}
}

func TestCheckOneChain(t *testing.T) {
	stubEnv(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/r1", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/r2", 302)
	})
	mux.HandleFunc("/r2", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/fin", 302)
	})
	mux.HandleFunc("/fin", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(goodPage))
	})
	ts := httptest.NewTLSServer(mux)
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/r1")
	if r.Error != "" {
		t.Fatalf("неожиданная ошибка: %s", r.Error)
	}
	if r.Checks[0].Got != 8 {
		t.Errorf("два прыжка: %+v, ждали 8", r.Checks[0])
	}
	if len(r.Hops) != 3 {
		t.Errorf("записей пути %d, ждали 3", len(r.Hops))
	}
}

func TestCheckOneGuarded(t *testing.T) {
	stubEnv(t)
	var otherPort string
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://localhost:"+otherPort+"/x", 302)
	}))
	defer ts.Close()
	port := testPort(ts)
	otherPort = port
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/")
	if r.Error != "" {
		t.Fatalf("неожиданная ошибка: %s", r.Error)
	}
	if r.Checks[0].Got != 0 || !strings.Contains(r.Checks[0].Note, "защита") {
		t.Errorf("переброс внутрь: %+v", r.Checks[0])
	}
}

func TestCheckOne404(t *testing.T) {
	stubEnv(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/gone")
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "ошибкой 404") {
			found = true
		}
	}
	if !found {
		t.Errorf("нет пометки про 404: %v", r.Notes)
	}
	if r.Checks[0].Got > 10 {
		t.Errorf("битая страница: редиректы %d, ждали не больше 10", r.Checks[0].Got)
	}
}

func TestCheckOneJSAndAffiliate(t *testing.T) {
	stubEnv(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html><body><script>location.replace("https://x.test/")</script></body></html>`))
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/p?utm_x=1")
	joined := strings.Join(r.Notes, "\n")
	if !strings.Contains(joined, "через скрипт") {
		t.Errorf("нет пометки про скрипт: %v", r.Notes)
	}
	if !strings.Contains(joined, "хвост") {
		t.Errorf("нет пометки про хвост: %v", r.Notes)
	}
}

func TestCheckOneCloak(t *testing.T) {
	stubEnv(t)
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.UserAgent(), "Pinterestbot") {
			http.Error(w, "no", 403)
			return
		}
		_, _ = w.Write([]byte(goodPage))
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/")
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "а боту") {
			found = true
		}
	}
	if !found {
		t.Errorf("маскировку не заметили: %v", r.Notes)
	}
}

func TestCheckOneGSBCap(t *testing.T) {
	stubEnv(t)
	oldGSB := gsbFn
	gsbFn = func(string) bool { return true }
	defer func() { gsbFn = oldGSB }()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(goodPage))
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/")
	if r.Score > 35 {
		t.Errorf("чёрный список Google: балл %d, ждали не больше 35", r.Score)
	}
}

func TestCheckOneLists(t *testing.T) {
	stubEnv(t)
	oldLists := listsFn
	listsFn = func(string, string) ([]string, bool) { return []string{"SURBL"}, false }
	defer func() { listsFn = oldLists }()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(goodPage))
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/")
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "SURBL") {
			found = true
		}
	}
	if !found {
		t.Errorf("список не заметили: %v", r.Notes)
	}
}

func TestCheckOneTrustMissing(t *testing.T) {
	stubEnv(t)
	page := `<html><body><p>` + strings.Repeat("купи сейчас! ", 100) + `</p></body></html>`
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(page))
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/")
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "страниц доверия") {
			found = true
		}
	}
	if !found {
		t.Errorf("нет пометки про страницы доверия: %v", r.Notes)
	}
}

func TestCheckOneBadInput(t *testing.T) {
	stubEnv(t)
	if r := checkOne("???"); r.Error == "" {
		t.Error("мусор на входе: ждали ошибку")
	}
	oldResolve := resolveFn
	resolveFn = func(string) (string, error) { return "", errTestDNS }
	defer func() { resolveFn = oldResolve }()
	if r := checkOne("https://testcheck.local/"); r.Error == "" {
		t.Error("нет DNS: ждали ошибку")
	}
}

func TestCheckOneYoungCap(t *testing.T) {
	stubEnv(t)
	m3 := 3
	oldAge := ageFn
	ageFn = func(string) *int { return &m3 }
	defer func() { ageFn = oldAge }()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(goodPage))
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/")
	if r.Score > 59 {
		t.Errorf("домену 3 мес.: балл %d, ждали не больше 59", r.Score)
	}
}

func TestCheckOneHalfYearCap(t *testing.T) {
	stubEnv(t)
	m8 := 8
	oldAge := ageFn
	ageFn = func(string) *int { return &m8 }
	defer func() { ageFn = oldAge }()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(goodPage))
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/")
	if r.Score > 79 {
		t.Errorf("домену 8 мес.: балл %d, ждали не больше 79", r.Score)
	}
	if r.Score < 60 {
		t.Errorf("домену 8 мес.: балл %d, ждали жёлтую зону", r.Score)
	}
}

func TestParseURIBL(t *testing.T) {
	for _, ip := range []string{"127.0.0.2", "127.0.0.4", "127.0.0.8", "127.0.0.14"} {
		if hit, _ := parseURIBL(ip); !hit {
			t.Errorf("parseURIBL(%s): ждали hit", ip)
		}
	}
	for _, ip := range []string{"127.0.0.1", "127.0.0.255"} {
		if hit, refused := parseURIBL(ip); hit || !refused {
			t.Errorf("parseURIBL(%s): ждали отказ", ip)
		}
	}
	if hit, refused := parseURIBL("1.2.3.4"); hit || refused {
		t.Error("чужой адрес сочли ответом")
	}
}

func TestCheckOneDropped(t *testing.T) {
	stubEnv(t)
	m120 := 120
	oldAge := ageFn
	ageFn = func(string) *int { return &m120 }
	defer func() { ageFn = oldAge }()
	oldWayback := waybackFn
	waybackFn = func(string) archiveInfo { return archiveInfo{first: "2026-01-05", months: 5, total: 12, ok: true} }
	defer func() { waybackFn = oldWayback }()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(goodPage))
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/")
	if r.Score > 59 {
		t.Errorf("перекупленный: балл %d, ждали не больше 59", r.Score)
	}
	found := false
	for _, n := range r.Notes {
		if strings.Contains(n, "перекупался") {
			found = true
		}
	}
	if !found {
		t.Errorf("нет пометки про перекупку: %v", r.Notes)
	}
}

func TestCheckOneOTX(t *testing.T) {
	stubEnv(t)
	oldOtx := otxFn
	otxFn = func(string) (int, string) { return 7, "ok" }
	defer func() { otxFn = oldOtx }()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(goodPage))
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/")
	if r.Score > 59 {
		t.Errorf("7 жалоб: балл %d, ждали не больше 59", r.Score)
	}
}

func TestCheckOneVT(t *testing.T) {
	stubEnv(t)
	oldVt := vtFn
	vtFn = func(string) (int, int, int, string) { return 3, 0, 90, "ok" }
	defer func() { vtFn = oldVt }()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(goodPage))
	}))
	defer ts.Close()
	port := testPort(ts)
	newScanClient = func() *http.Client { return testClient(port) }

	r := checkOne("https://testcheck.local:" + port + "/")
	if r.Score > 35 {
		t.Errorf("3 вердикта: балл %d, ждали не больше 35", r.Score)
	}
}

func TestLooksLikeKey(t *testing.T) {
	if !looksLikeKey("AIzaSyAbcdef1234567890") {
		t.Error("нормальный ключ забраковали")
	}
	for _, bad := range []string{"", "short", "has space inside key 123", "tab\there"} {
		if looksLikeKey(bad) {
			t.Errorf("мусор %q сошёл за ключ", bad)
		}
	}
}

func TestKeysAPI(t *testing.T) {
	rec := httptest.NewRecorder()
	apiKeys(rec, httptest.NewRequest("GET", "/api/keys", nil))
	var st map[string]bool
	if err := json.Unmarshal(rec.Body.Bytes(), &st); err != nil {
		t.Fatalf("статус ключей не JSON: %v", err)
	}
	for _, k := range []string{"google", "otx", "vt"} {
		if _, ok := st[k]; !ok {
			t.Errorf("нет поля %q в статусе", k)
		}
	}
	bad := func(body string) map[string]any {
		r := httptest.NewRecorder()
		apiKeys(r, httptest.NewRequest("POST", "/api/keys", strings.NewReader(body)))
		var j map[string]any
		_ = json.Unmarshal(r.Body.Bytes(), &j)
		return j
	}
	if j := bad(`{"which":"nasa","key":"AIzaSyAbcdef1234567890"}`); j["ok"] != false {
		t.Error("неизвестный ключ приняли")
	}
	if j := bad(`{"which":"google","key":"short"}`); j["ok"] != false {
		t.Error("короткий ключ приняли")
	}
	if j := bad(`not json`); j["ok"] != false {
		t.Error("мусор приняли")
	}
	rec2 := httptest.NewRecorder()
	apiKeys(rec2, httptest.NewRequest("PUT", "/api/keys", nil))
	if rec2.Code != http.StatusMethodNotAllowed {
		t.Errorf("PUT: код %d, ждали 405", rec2.Code)
	}
}

func TestTLSInfoReal(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer ts.Close()
	addr := ts.Listener.Addr().String()
	oldSkip := tlsSkipVerify
	tlsSkipVerify = true
	defer func() { tlsSkipVerify = oldSkip }()
	out := tlsInfo(addr, "x.test")
	if !out.ok || out.daysLeft <= 0 {
		t.Errorf("настоящий TLS: %+v", out)
	}
}
