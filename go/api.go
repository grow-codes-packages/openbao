package openbao

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// envelope is the standard OpenBao response body.
type envelope struct {
	RequestID     string          `json:"request_id"`
	LeaseID       string          `json:"lease_id"`
	Renewable     bool            `json:"renewable"`
	LeaseDuration int64           `json:"lease_duration"`
	Data          json.RawMessage `json:"data"`
	WrapInfo      *wrapInfoJSON   `json:"wrap_info"`
	Warnings      []string        `json:"warnings"`
	Auth          *authJSON       `json:"auth"`

	status int
	op     string
}

// decodeData decodes data into out; a missing or null data leaves out unchanged.
func (e *envelope) decodeData(out any) error {
	if out == nil || len(e.Data) == 0 || bytes.Equal(e.Data, []byte("null")) {
		return nil
	}
	if err := json.Unmarshal(e.Data, out); err != nil {
		return &Error{Code: ErrorCodeUnavailable, Message: e.op + ": unexpected response data", HTTPStatus: e.status}
	}
	return nil
}

type authJSON struct {
	ClientToken   string            `json:"client_token"`
	Accessor      string            `json:"accessor"`
	Policies      []string          `json:"policies"`
	TokenPolicies []string          `json:"token_policies"`
	Metadata      map[string]string `json:"metadata"`
	LeaseDuration int64             `json:"lease_duration"`
	Renewable     bool              `json:"renewable"`
	EntityID      string            `json:"entity_id"`
	TokenType     string            `json:"token_type"`
	Orphan        bool              `json:"orphan"`
	NumUses       int               `json:"num_uses"`
}

func (a *authJSON) info() *AuthInfo {
	if a == nil {
		return nil
	}
	return &AuthInfo{
		ClientToken:   NewSecret(a.ClientToken),
		Accessor:      a.Accessor,
		Policies:      a.Policies,
		TokenPolicies: a.TokenPolicies,
		Metadata:      a.Metadata,
		LeaseDuration: seconds(a.LeaseDuration),
		Renewable:     a.Renewable,
		EntityID:      a.EntityID,
		TokenType:     a.TokenType,
		Orphan:        a.Orphan,
		NumUses:       a.NumUses,
	}
}

type wrapInfoJSON struct {
	Token        string   `json:"token"`
	Accessor     string   `json:"accessor"`
	TTL          int64    `json:"ttl"`
	CreationTime flexTime `json:"creation_time"`
	CreationPath string   `json:"creation_path"`
}

func (w *wrapInfoJSON) info() *WrapInfo {
	if w == nil {
		return nil
	}
	return &WrapInfo{
		Token:        NewSecret(w.Token),
		Accessor:     w.Accessor,
		TTL:          seconds(w.TTL),
		CreationTime: w.CreationTime.Time,
		CreationPath: w.CreationPath,
	}
}

// SecretResponse is a full OpenBao response (used by Unwrap, whose payload can
// be any API response).
type SecretResponse struct {
	RequestID     string
	LeaseID       string
	Renewable     bool
	LeaseDuration time.Duration
	// Data is the response data (the wrapped map for a Wrap token).
	Data     map[string]any
	Warnings []string
	// Auth is set when the response carried a token (login, token create).
	Auth *AuthInfo
	// WrapInfo is set when the response itself was wrapped.
	WrapInfo *WrapInfo
}

func (e *envelope) secretResponse() (*SecretResponse, error) {
	var data map[string]any
	if err := e.decodeData(&data); err != nil {
		return nil, err
	}
	return &SecretResponse{
		RequestID: e.RequestID, LeaseID: e.LeaseID, Renewable: e.Renewable,
		LeaseDuration: seconds(e.LeaseDuration), Data: data, Warnings: e.Warnings,
		Auth: e.Auth.info(), WrapInfo: e.WrapInfo.info(),
	}, nil
}

// flexTime decodes RFC 3339 strings, unix seconds (number or numeric string),
// empty strings and null (zero time).
type flexTime struct{ time.Time }

func (t *flexTime) UnmarshalJSON(b []byte) error {
	t.Time = time.Time{}
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" || s == "0" {
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		t.Time = time.Unix(n, 0).UTC()
		return nil
	}
	if v, err := time.Parse(time.RFC3339Nano, s); err == nil {
		t.Time = v
	}
	return nil
}

// flexDuration decodes integer seconds or Go duration strings ("720h0m0s").
type flexDuration struct{ time.Duration }

func (d *flexDuration) UnmarshalJSON(b []byte) error {
	d.Duration = 0
	s := strings.Trim(string(b), `"`)
	if s == "" || s == "null" {
		return nil
	}
	if n, err := strconv.ParseInt(s, 10, 64); err == nil {
		d.Duration = seconds(n)
		return nil
	}
	if v, err := time.ParseDuration(s); err == nil {
		d.Duration = v
	}
	return nil
}

func seconds(n int64) time.Duration { return time.Duration(n) * time.Second }

// durationString renders d as whole seconds ("90s"); sub-second positive
// durations round up to "1s".
func durationString(d time.Duration) string {
	s := int64(d / time.Second)
	if d%time.Second != 0 {
		s++
	}
	return fmt.Sprintf("%ds", s)
}

func jsonMarshal(v any) ([]byte, error) { return json.Marshal(v) }

// joinPath joins path segments with "/", dropping empty segments and
// surrounding slashes.
func joinPath(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p = strings.Trim(p, "/"); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "/")
}

// mountOr returns mount without slashes, or def when empty.
func mountOr(mount, def string) string {
	if m := strings.Trim(mount, "/"); m != "" {
		return m
	}
	return def
}

// requireArg returns a VALIDATION error when value is empty.
func requireArg(op, name, value string) error {
	if strings.TrimSpace(value) == "" {
		return ValidationError(op, name+" is required")
	}
	return nil
}

// Ptr returns a pointer to v (for optional fields such as KVMetadataOptions.MaxVersions).
func Ptr[T any](v T) *T { return &v }
