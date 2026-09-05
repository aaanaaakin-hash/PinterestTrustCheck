// Живые доказательства: боевые сайты и настоящие ключи.
// Запускаются только с PINTEREST_LIVE=1, обычный прогон их пропускает.
package main

import (
	"os"
	"strings"
	"testing"
)

func needLive(t *testing.T) {
	t.Helper()
	if os.Getenv("PINTEREST_LIVE") == "" {
		t.Skip("только вживую: PINTEREST_LIVE=1")
	}
}

func TestLiveURIBLTestpoint(t *testing.T) {
	needLive(t)
	hit, refused := uriblListed("2.0.0.127")
	if refused {
		t.Log("сеть отклонена URIBL — засчитано как «не знаем», ложного обвинения нет")
		return
	}
	if !hit {
		t.Error("контрольная точка URIBL не опознана")
	}
}

func TestLiveGSB(t *testing.T) {
	needLive(t)
	if loadGSBKey() == "" {
		t.Skip("нет ключа Google")
	}
	if !gsbListed("https://testsafebrowsing.appspot.com/s/malware.html") {
		t.Error("тестовая страница Google не опознана — ключ или запрос не работают")
	}
}

func TestLiveOTX(t *testing.T) {
	needLive(t)
	if loadOTXKey() == "" {
		t.Skip("нет ключа OTX")
	}
	n, st := otxPulses("testsafebrowsing.appspot.com")
	if st != "ok" {
		t.Errorf("OTX не ответил как надо: %s", st)
	} else {
		t.Logf("жалоб OTX: %d", n)
	}
}

func TestLiveVT(t *testing.T) {
	needLive(t)
	if loadVTKey() == "" {
		t.Skip("нет ключа VT")
	}
	m, s, tot, st := vtStats("testsafebrowsing.appspot.com")
	if st != "ok" && st != "limited" {
		t.Errorf("VirusTotal не ответил как надо: %s", st)
	} else {
		t.Logf("VT: вредоносных %d, подозрительных %d, всего %d", m, s, tot)
	}
}

func TestLiveBadSSL(t *testing.T) {
	needLive(t)
	r := checkOne("https://expired.badssl.com/")
	if r.Error != "" {
		t.Fatalf("неожиданная ошибка: %s", r.Error)
	}
	for _, c := range r.Checks {
		if c.Name == "Шифрование" && c.Got != 0 {
			t.Errorf("протухший сертификат: %+v", c)
		}
	}
}

func TestLiveDelay(t *testing.T) {
	needLive(t)
	r := checkOne("https://httpbin.org/delay/3")
	if r.Error != "" {
		t.Fatalf("неожиданная ошибка: %s", r.Error)
	}
	for _, c := range r.Checks {
		if c.Name == "Скорость" && c.Got != 2 {
			t.Errorf("медленная страница: %+v", c)
		}
	}
}

func TestLiveGuard(t *testing.T) {
	needLive(t)
	r := checkOne("https://httpbin.org/redirect-to?url=http://127.0.0.1/")
	found := false
	for _, c := range r.Checks {
		if c.Name == "Редиректы" && strings.Contains(c.Note, "защита") {
			found = true
		}
	}
	if !found {
		t.Errorf("переброс внутрь не остановлен: %+v", r.Checks)
	}
}
