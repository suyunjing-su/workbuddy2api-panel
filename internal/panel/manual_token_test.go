package panel

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
	"github.com/misakano7545/workbuddy2api-panel/internal/pool"
	"github.com/misakano7545/workbuddy2api-panel/internal/upstream"
)

func TestAddManualTokenSavesRefreshedCNAccount(t *testing.T) {
	up := &upstream.Client{
		HTTP: &http.Client{Transport: manualTokenRoundTrip(func(r *http.Request) (*http.Response, error) {
			var body string
			switch {
			case strings.HasSuffix(r.URL.Path, "/v2/plugin/auth/token/refresh"):
				body = `{"code":0,"data":{"accessToken":"new-at","refreshToken":"new-rt","expiresIn":3600,"domain":"www.workbuddy.cn"}}`
			case strings.HasSuffix(r.URL.Path, "/console/account"):
				body = `{"code":0,"data":{"uid":"cn-manual-1","nickname":"手动账号","enterpriseId":"ent-1"}}`
			case strings.HasSuffix(r.URL.Path, "/v2/billing/meter/get-enterprise-user-usage"):
				body = `{"code":0,"data":{"credit":1,"limitNum":10,"cycleEndTime":"2099-01-01 00:00:00"}}`
			default:
				return nil, &manualTokenError{message: "unexpected path: " + r.URL.Path}
			}
			return &http.Response{
				StatusCode: 200,
				Header:     http.Header{"Content-Type": []string{"application/json"}},
				Body:       io.NopCloser(strings.NewReader(body)),
			}, nil
		})},
		ChatBaseCN:    "https://cn.example",
		BillingBaseCN: "https://cn.example",
		WebBaseCN:     "https://cn.example",
	}
	p := New(Config{Pool: pool.New(""), Upstream: up, AuthDir: t.TempDir()})
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, httptest.NewRequest("POST", "/panel/api/accounts/add_token",
		strings.NewReader(`{"access_token":"old-at","refresh_token":"old-rt"}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d body=%s", rec.Code, rec.Body)
	}
	a := p.cfg.Pool.AuthByUID("cn-manual-1")
	if a == nil {
		t.Fatal("manual token account should be loaded into pool")
	}
	if a.AccessToken != "new-at" || a.RefreshToken != "new-rt" {
		t.Fatalf("tokens=%q/%q want refreshed tokens", a.AccessToken, a.RefreshToken)
	}
	if a.Realm() != "cn" {
		t.Fatalf("realm=%q want cn", a.Realm())
	}
	auths, err := auth.LoadDir(p.cfg.AuthDir)
	if err != nil || len(auths) != 1 {
		t.Fatalf("saved auths=%d err=%v", len(auths), err)
	}
}

func TestAddManualTokenRejectsWithoutPersisting(t *testing.T) {
	for name, body := range map[string]string{
		"missing access token":  `{"refresh_token":"rt"}`,
		"missing refresh token": `{"access_token":"at"}`,
		"static api key":        `{"access_token":"ck_id.secret","refresh_token":"rt"}`,
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			p := New(Config{Pool: pool.New(""), AuthDir: dir})
			rec := httptest.NewRecorder()
			p.ServeHTTP(rec, httptest.NewRequest("POST", "/panel/api/accounts/add_token", strings.NewReader(body)))
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("code=%d body=%s want 400", rec.Code, rec.Body)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 || len(p.cfg.Pool.List()) != 0 {
				t.Fatalf("rejected account was persisted or loaded: files=%d accounts=%d", len(entries), len(p.cfg.Pool.List()))
			}
		})
	}
}

type manualTokenRoundTrip func(*http.Request) (*http.Response, error)

func (f manualTokenRoundTrip) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type manualTokenError struct{ message string }

func (e *manualTokenError) Error() string { return e.message }
