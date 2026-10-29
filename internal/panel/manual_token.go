package panel

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/misakano7545/workbuddy2api-panel/internal/auth"
)

// addManualToken 添加国内版 OAuth 令牌账号。
//
// POST /panel/api/accounts/add_token
// body: {"access_token":"...","refresh_token":"..."}
//
// 先用 CN 官网资料端点校验 access token 并发现 uid，再落盘、热加载及执行
// 与 OAuth 登录相同的签到/余额初始化流程。此入口不接受 realm/domain 参数。
func (p *Panel) addManualToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&body); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid json")
		return
	}
	at, rt := strings.TrimSpace(body.AccessToken), strings.TrimSpace(body.RefreshToken)
	if at == "" || rt == "" {
		writeErr(w, http.StatusBadRequest, "access_token 和 refresh_token 均为必填项")
		return
	}
	if (&auth.Auth{AccessToken: at}).IsAPIKey() {
		writeErr(w, http.StatusBadRequest, "不支持静态 API Key，请使用 OAuth access token")
		return
	}

	probe := &auth.Auth{AccessToken: at, RefreshToken: rt}
	// 固定 CN realm，确保 refresh 响应里的 domain 不会把后续请求切到国际端点。
	_, _ = auth.BackfillRealmFor(probe, "cn")
	// 先强制刷新一次：既验证 refresh token 有效，又拿到上游最新的 access/refresh
	// token 与过期时间，避免把只验证了 AT 的半有效凭证写入账号池。
	if err := p.cfg.Upstream.RefreshToken(probe); err != nil {
		writeErr(w, http.StatusBadRequest, "refresh token 无效或刷新失败："+err.Error())
		return
	}
	uid, nickname, enterpriseID, err := p.cfg.Upstream.FetchAccountIdentity(probe)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "access token 无效或账号信息查询失败："+err.Error())
		return
	}
	if !validUID(uid) {
		writeErr(w, http.StatusBadRequest, "上游未返回有效 uid，拒绝落盘")
		return
	}

	expiresAt := probe.ExpiresAt
	if expiresAt <= 0 {
		expiresAt = tokenExpiry(probe.AccessToken)
	}
	domain := probe.Domain
	if domain == "" {
		domain = "www.workbuddy.cn"
	}
	a := &auth.Auth{
		AccessToken:  probe.AccessToken,
		RefreshToken: probe.RefreshToken,
		ExpiresAt:    expiresAt,
		Domain:       domain,
		UID:          uid,
		Nickname:     nickname,
		EnterpriseID: enterpriseID,
		FilePath:     filepath.Join(p.cfg.AuthDir, fmt.Sprintf("workbuddy-%s.json", uid)),
	}
	if _, err := auth.BackfillRealmFor(a, "cn"); err != nil {
		writeErr(w, http.StatusInternalServerError, "set realm: "+err.Error())
		return
	}
	if err := os.MkdirAll(p.cfg.AuthDir, 0o755); err != nil {
		writeErr(w, http.StatusInternalServerError, "mkdir auth dir: "+err.Error())
		return
	}
	if err := a.SaveAtomic(); err != nil {
		writeErr(w, http.StatusInternalServerError, "save auth: "+err.Error())
		return
	}
	isNewAccount := p.cfg.Pool.AuthByUID(uid) == nil
	p.cfg.Pool.Add(a)
	p.cfg.Pool.Revive(uid)

	checkinMsg := ""
	if !a.IsEnterprise() {
		if err := p.cfg.Upstream.DailyCheckin(a); err != nil {
			checkinMsg = err.Error()
		}
	}
	remain, total := int64(-1), int64(0)
	balanceErr := ""
	if rm, tt, err := p.cfg.Upstream.UserResource(a); err == nil {
		remain, total = rm, tt
		p.cfg.Pool.ReenableIfCredits(uid, rm, tt)
	} else {
		balanceErr = err.Error()
	}
	if isNewAccount {
		p.StartNewAccountTasks(uid)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "uid": uid, "nickname": nickname, "realm": "cn",
		"credits": remain, "credits_total": total,
		"checkin_message": checkinMsg, "balance_error": balanceErr,
	})
}

func tokenExpiry(token string) int64 {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Now().Add(time.Hour).Unix()
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Now().Add(time.Hour).Unix()
	}
	var claims struct {
		ExpiresAt int64 `json:"exp"`
	}
	if json.Unmarshal(payload, &claims) != nil || claims.ExpiresAt <= time.Now().Unix() {
		return time.Now().Add(time.Hour).Unix()
	}
	return claims.ExpiresAt
}
