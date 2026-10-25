package creds

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// OIDC exchanges the workload's ID token (read fresh from TokenFile each time, since issuers
// rotate it) for a short-lived key of Bot: POST /v1/organizations/:org/bots/:bot/oidc-api-keys.
// The token is the request's only credential. The key is used until 5 minutes before it expires.
type OIDC struct {
	OrgsURL, Organization, Bot, TokenFile string
	HTTP                                  *http.Client
	Now                                   func() time.Time

	mu        sync.Mutex
	key       string
	expiresAt time.Time // zero: no expiry given
}

func (o *OIDC) now() time.Time {
	if o.Now != nil {
		return o.Now()
	}
	return time.Now()
}

func (o *OIDC) Key(ctx context.Context) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.key != "" && (o.expiresAt.IsZero() || o.now().Add(instanceRefreshMargin).Before(o.expiresAt)) {
		return o.key, nil
	}
	b, err := os.ReadFile(o.TokenFile)
	if err != nil {
		return "", err
	}
	body, _ := json.Marshal(map[string]string{"token": strings.TrimSpace(string(b)), "name": "ezgh-systems-agent"})
	u := strings.TrimRight(o.OrgsURL, "/") + "/v1/organizations/" + url.PathEscape(o.Organization) + "/bots/" + url.PathEscape(o.Bot) + "/oidc-api-keys"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	c := o.HTTP
	if c == nil {
		c = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", fmt.Errorf("OIDC exchange: %w", err)
	}
	defer resp.Body.Close()
	rb, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC exchange answered %d %s", resp.StatusCode, errorCode(rb))
	}
	var out struct {
		APIKey struct {
			ExpiresAt *time.Time `json:"expiresAt"`
		} `json:"apiKey"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rb, &out); err != nil || out.Token == "" {
		return "", fmt.Errorf("OIDC exchange sent an unreadable answer")
	}
	o.key, o.expiresAt = out.Token, time.Time{}
	if out.APIKey.ExpiresAt != nil {
		o.expiresAt = *out.APIKey.ExpiresAt
	}
	return o.key, nil
}

func (o *OIDC) Invalidate(refused string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.key == refused {
		o.key = ""
	}
}
