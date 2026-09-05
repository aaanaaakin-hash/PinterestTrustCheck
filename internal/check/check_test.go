package check_test

import (
	"strings"
	"testing"

	"trustcheck/internal/check"
)

func TestValidHost(t *testing.T) {
	good := []string{"amazon.com", "a-b.example-domain.co", "x.y", "123.com"}
	for _, h := range good {
		if !check.ValidHost(h) {
			t.Errorf("ValidHost(%q) = false, ждали true", h)
		}
	}
	bad := []string{"", "-abc.com", "abc-.com", "a..com", "exa_mple.com", "Example.COM", "a/b.com", strings.Repeat("a", 64) + ".com"}
	for _, h := range bad {
		if check.ValidHost(h) {
			t.Errorf("ValidHost(%q) = true, ждали false", h)
		}
	}
}

func TestToStartURL(t *testing.T) {
	cases := []struct {
		in    string
		host  string
		start string
	}{
		{"amazon.com", "amazon.com", "https://amazon.com/"},
		{"https://example.com/some/page?utm_source=x", "example.com", "https://example.com/some/page?utm_source=x"},
		{"http://example.com", "example.com", "https://example.com/"},
		{"  Example.COM/path/  ", "example.com", "https://example.com/path/"},
		{"example.com.", "example.com", "https://example.com/"},
		{"8.8.8.8", "8.8.8.8", "https://8.8.8.8/"},
	}
	for _, c := range cases {
		host, start, err := check.ToStartURL(c.in)
		if err != nil || host != c.host || start != c.start {
			t.Errorf("ToStartURL(%q) = (%q, %q, %v), ждали (%q, %q, nil)", c.in, host, start, err, c.host, c.start)
		}
	}
	bad := []string{"", "nota real domain!!", "localhost", "ftp://example.com/x", "http://user:pass@example.com/", "http://10.0.0.1/", "http://127.0.0.1/", "nodot", "ab"}
	for _, in := range bad {
		if _, _, err := check.ToStartURL(in); err == nil {
			t.Errorf("ToStartURL(%q): ждали ошибку, её нет", in)
		}
	}
}

func TestVerdictOf(t *testing.T) {
	cases := []struct {
		score int
		word  string
	}{
		{100, "ЗЕЛЁНЫЙ"}, {80, "ЗЕЛЁНЫЙ"}, {79, "ЖЁЛТЫЙ"}, {60, "ЖЁЛТЫЙ"},
		{59, "ОРАНЖЕВЫЙ"}, {40, "ОРАНЖЕВЫЙ"}, {39, "КРАСНЫЙ"}, {0, "КРАСНЫЙ"}, {-5, "КРАСНЫЙ"},
	}
	for _, c := range cases {
		if _, word := check.VerdictOf(c.score); word != c.word {
			t.Errorf("VerdictOf(%d) = %q, ждали %q", c.score, word, c.word)
		}
	}
}

func TestSameSite(t *testing.T) {
	if !check.SameSite("www.amazon.com", "amazon.com") {
		t.Error("поддомен — тот же сайт")
	}
	if !check.SameSite("amazon.com", "amazon.com") {
		t.Error("тот же домен — тот же сайт")
	}
	if check.SameSite("evil-amazon.com", "amazon.com") {
		t.Error("похожий чужой домен — не тот же сайт")
	}
	if check.SameSite("a.com", "b.com") {
		t.Error("разные домены — не тот же сайт")
	}
}

func TestHasSuffixAny(t *testing.T) {
	list := []string{"bit.ly", "workers.dev"}
	if !check.HasSuffixAny("bit.ly", list) {
		t.Error("точное совпадение не нашли")
	}
	if !check.HasSuffixAny("x.workers.dev", list) {
		t.Error("поддомен не нашли")
	}
	if check.HasSuffixAny("notbit.ly.evil.com", list) {
		t.Error("ложное срабатывание на чужом домене")
	}
	if check.HasSuffixAny("mybit.ly", list) {
		t.Error("ложное срабатывание на похожем имени")
	}
}

func TestHasJsRedirect(t *testing.T) {
	if check.HasJsRedirect(`<meta http-equiv="refresh" content="0;url=x">`) == "" {
		t.Error("meta-refresh не нашли")
	}
	if check.HasJsRedirect(`location.replace("https://evil.com")`) == "" {
		t.Error("location.replace не нашли")
	}
	if check.HasJsRedirect(`<script>window.location="https://evil.com"</script>`) == "" {
		t.Error("переброс на маленькой странице не нашли")
	}
	big := `<html><body>` + strings.Repeat(`<p>текст window.location в обычном коде</p>`, 2000) + `</body></html>`
	if check.HasJsRedirect(big) != "" {
		t.Error("ложное срабатывание на большой странице")
	}
	if check.HasJsRedirect(`<html><body>Обычная страница</body></html>`) != "" {
		t.Error("ложное срабатывание на чистой странице")
	}
}

func TestCompactChecks(t *testing.T) {
	parts := []check.CheckPart{
		{Name: "Редиректы", Got: 25, Max: 30},
		{Name: "Шифрование", Got: 25, Max: 25},
		{Name: "Скорость", Got: 6, Max: 10},
		{Name: "Заголовки", Got: 1, Max: 5},
		{Name: "Возраст", Got: 5, Max: 15},
		{Name: "Без хвостов", Got: 5, Max: 15},
		{Name: "Что-то новое", Got: 9, Max: 9},
	}
	if got := check.CompactChecks(parts); got != "R25 T25 S6 H1 A5 C5" {
		t.Errorf("CompactChecks = %q, ждали R25 T25 S6 H1 A5 C5", got)
	}
}

func TestServeAddr(t *testing.T) {
	t.Setenv("PINTEREST_PORT", "")
	if got := check.ServeAddr(); got != "127.0.0.1:18743" {
		t.Errorf("пустой порт: %q", got)
	}
	t.Setenv("PINTEREST_PORT", "18744")
	if got := check.ServeAddr(); got != "127.0.0.1:18744" {
		t.Errorf("порт 18744: %q", got)
	}
	for _, bad := range []string{"abc", "12:34", "1;rm", "123456", "8.8.8.8"} {
		t.Setenv("PINTEREST_PORT", bad)
		if got := check.ServeAddr(); got != "127.0.0.1:18743" {
			t.Errorf("мусор %q: %q, ждали стандартный", bad, got)
		}
	}
}

func TestHostOf(t *testing.T) {
	if got := check.HostOf("https://WWW.Example.com:443/a?b=c"); got != "www.example.com" {
		t.Errorf("HostOf = %q", got)
	}
	if got := check.HostOf("://bad"); got != "" {
		t.Errorf("HostOf мусора = %q, ждали пусто", got)
	}
}
