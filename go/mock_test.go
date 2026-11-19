package openbao

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fixtureFile is a response recorded against the real openbao/openbao:2.7.2
// container (testdata/fixtures, secrets replaced by "<redacted>").
type fixtureFile struct {
	Request struct {
		Method string          `json:"method"`
		Path   string          `json:"path"`
		Body   json.RawMessage `json:"body"`
	} `json:"request"`
	Response struct {
		Status  int             `json:"status"`
		Headers []string        `json:"headers"`
		Body    json.RawMessage `json:"body"`
	} `json:"response"`
}

func loadFixture(t *testing.T, name string) fixtureFile {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "fixtures", name+".json"))
	if err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	var f fixtureFile
	if err := json.Unmarshal(data, &f); err != nil {
		t.Fatalf("fixture %s: %v", name, err)
	}
	return f
}

// reply is one canned response.
type reply struct {
	status int
	header http.Header
	body   []byte
}

// recorded is one request seen by the mock.
type recorded struct {
	Method string
	Path   string
	Query  string
	Header http.Header
	Body   []byte
}

// JSON decodes the recorded body.
func (r recorded) JSON(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.Body, &m); err != nil {
		t.Fatalf("request body %q: %v", r.Body, err)
	}
	return m
}

// mockBao serves canned replies per "METHOD /path" (query ignored); several
// replies for one route are served in order and the last one repeats.
// Unknown routes answer 404 {"errors":[]} like OpenBao.
type mockBao struct {
	*httptest.Server
	t      *testing.T
	mu     sync.Mutex
	routes map[string][]reply
	served map[string]int
	reqs   []recorded
}

func newMockBao(t *testing.T) *mockBao {
	t.Helper()
	m := &mockBao{t: t, routes: map[string][]reply{}, served: map[string]int{}}
	m.Server = httptest.NewServer(http.HandlerFunc(m.serve))
	t.Cleanup(m.Close)
	return m
}

func (m *mockBao) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	key := r.Method + " " + r.URL.Path
	m.mu.Lock()
	m.reqs = append(m.reqs, recorded{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery, Header: r.Header.Clone(), Body: body})
	replies := m.routes[key]
	var rep reply
	if len(replies) == 0 {
		rep = reply{status: http.StatusNotFound, body: []byte(`{"errors":[]}`)}
	} else {
		i := m.served[key]
		if i >= len(replies) {
			i = len(replies) - 1
		}
		m.served[key]++
		rep = replies[i]
	}
	m.mu.Unlock()
	for k, vs := range rep.header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	if w.Header().Get("Content-Type") == "" && len(rep.body) > 0 {
		w.Header().Set("Content-Type", "application/json")
	}
	w.WriteHeader(rep.status)
	_, _ = w.Write(rep.body)
}

func (m *mockBao) add(method, path string, rep reply) *mockBao {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := method + " " + path
	m.routes[key] = append(m.routes[key], rep)
	return m
}

// fixture registers a recorded fixture's response for method + path.
func (m *mockBao) fixture(method, path, name string) *mockBao {
	m.t.Helper()
	f := loadFixture(m.t, name)
	h := http.Header{}
	for _, line := range f.Response.Headers {
		k, v, _ := strings.Cut(line, ":")
		h.Add(strings.TrimSpace(k), strings.TrimSpace(v))
	}
	body := []byte(f.Response.Body)
	var s string
	if !strings.Contains(h.Get("Content-Type"), "json") && json.Unmarshal(body, &s) == nil {
		body = []byte(s) // raw (non-JSON) body such as PEM
	}
	if string(body) == "null" || f.Response.Status == http.StatusNoContent {
		body = nil
	}
	return m.add(method, path, reply{status: f.Response.Status, header: h, body: body})
}

// json registers a JSON reply.
func (m *mockBao) json(method, path string, status int, body any) *mockBao {
	m.t.Helper()
	b, err := json.Marshal(body)
	if err != nil {
		m.t.Fatal(err)
	}
	return m.add(method, path, reply{status: status, body: b})
}

// data registers a 200 envelope with data.
func (m *mockBao) data(method, path string, data any) *mockBao {
	return m.json(method, path, http.StatusOK, map[string]any{"request_id": "r1", "data": data})
}

// noContent registers a 204.
func (m *mockBao) noContent(method, path string) *mockBao {
	return m.add(method, path, reply{status: http.StatusNoContent})
}

// errors registers an OpenBao error reply.
func (m *mockBao) errors(method, path string, status int, msgs ...string) *mockBao {
	if msgs == nil {
		msgs = []string{}
	}
	return m.json(method, path, status, map[string]any{"errors": msgs})
}

// requests returns the recorded requests.
func (m *mockBao) requests() []recorded {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]recorded(nil), m.reqs...)
}

// last returns the last request for method + path.
func (m *mockBao) last(method, path string) recorded {
	m.t.Helper()
	reqs := m.requests()
	for i := len(reqs) - 1; i >= 0; i-- {
		if reqs[i].Method == method && reqs[i].Path == path {
			return reqs[i]
		}
	}
	m.t.Fatalf("no request %s %s (have %d requests)", method, path, len(reqs))
	return recorded{}
}

// count returns how many requests hit method + path.
func (m *mockBao) count(method, path string) int {
	n := 0
	for _, r := range m.requests() {
		if r.Method == method && r.Path == path {
			n++
		}
	}
	return n
}

// newBao returns a client for m with no retries and a test token.
func newBao(t *testing.T, m *mockBao, mutate func(*Config)) *Client {
	t.Helper()
	return newTestClient(t, m.URL, func(c *Config) {
		c.Retry = fastRetry(0)
		if mutate != nil {
			mutate(c)
		}
	})
}

// fakeClock advances instantly: After(d) moves the clock by d and fires at once.
type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{now: time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)}
}

func (f *fakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeClock) After(d time.Duration) <-chan time.Time {
	f.mu.Lock()
	f.now = f.now.Add(d)
	now := f.now
	f.mu.Unlock()
	ch := make(chan time.Time, 1)
	ch <- now
	return ch
}

// blockClock never fires (for stop tests).
type blockClock struct{}

func (blockClock) Now() time.Time                       { return time.Now() }
func (blockClock) After(time.Duration) <-chan time.Time { return make(chan time.Time) }

func waitDone(t *testing.T, done <-chan struct{}) {
	t.Helper()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("background loop did not finish")
	}
}

func wantCode(t *testing.T, err error, code ErrorCode) {
	t.Helper()
	if CodeOf(err) != code {
		t.Fatalf("want %s, got %v", code, err)
	}
}
