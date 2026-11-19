package openbao_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeKV is a small in-memory OpenBao KV server (KV v2 at "secret", KV v1 at
// "kv1") that follows the wire behaviour recorded from openbao/openbao:2.7.2:
// 204 for deletes of missing paths, 404 {"errors":[]} for missing reads and
// lists, CAS mismatch as 400, soft deletes keep metadata.
type fakeKV struct {
	*httptest.Server
	mu sync.Mutex
	v2 map[string]*fakeSecret
	v1 map[string]map[string]any
}

type fakeVersion struct {
	data    map[string]any
	created time.Time
	deleted time.Time
}

type fakeSecret struct {
	versions map[int]*fakeVersion
	current  int
	custom   map[string]string
	created  time.Time
	updated  time.Time
}

func newFakeKV(t *testing.T) *fakeKV {
	t.Helper()
	f := &fakeKV{v2: map[string]*fakeSecret{}, v1: map[string]map[string]any{}}
	f.Server = httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.Close)
	return f
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func notFound(w http.ResponseWriter) {
	writeJSON(w, http.StatusNotFound, map[string]any{"errors": []string{}})
}

func listKeys(paths []string, prefix string) []string {
	if prefix != "" {
		prefix += "/"
	}
	set := map[string]bool{}
	for _, p := range paths {
		rest, ok := strings.CutPrefix(p, prefix)
		if !ok || rest == "" {
			continue
		}
		if i := strings.Index(rest, "/"); i >= 0 {
			set[rest[:i+1]] = true
		} else {
			set[rest] = true
		}
	}
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func (f *fakeKV) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var body map[string]any
	raw, _ := io.ReadAll(r.Body)
	_ = json.Unmarshal(raw, &body)
	path := strings.TrimPrefix(r.URL.Path, "/v1/")
	list := r.URL.Query().Get("list") == "true"
	switch {
	case strings.HasPrefix(path, "sys/internal/ui/mounts/"):
		mount := strings.SplitN(strings.TrimPrefix(path, "sys/internal/ui/mounts/"), "/", 2)[0]
		version := map[string]string{"secret": "2", "kv1": "1"}[mount]
		if version == "" {
			writeJSON(w, http.StatusForbidden, map[string]any{"errors": []string{"preflight capability check returned 403"}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"type": "kv", "options": map[string]string{"version": version}}})
	case strings.HasPrefix(path, "kv1/"):
		f.serveV1(w, r, strings.TrimPrefix(path, "kv1/"), body, list)
	case path == "kv1" && list:
		f.serveV1(w, r, "", body, list)
	case strings.HasPrefix(path, "secret/"):
		rest := strings.TrimPrefix(path, "secret/")
		kind, key, _ := strings.Cut(rest, "/")
		f.serveV2(w, r, kind, key, body, list)
	default:
		notFound(w)
	}
}

func (f *fakeKV) serveV1(w http.ResponseWriter, r *http.Request, key string, body map[string]any, list bool) {
	switch {
	case list:
		paths := make([]string, 0, len(f.v1))
		for p := range f.v1 {
			paths = append(paths, p)
		}
		keys := listKeys(paths, key)
		if len(keys) == 0 {
			notFound(w)
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"keys": keys}})
	case r.Method == http.MethodGet:
		d, ok := f.v1[key]
		if !ok {
			notFound(w)
			return
		}
		writeJSON(w, 200, map[string]any{"data": d, "lease_duration": 2764800})
	case r.Method == http.MethodPost || r.Method == http.MethodPut:
		f.v1[key] = body
		w.WriteHeader(http.StatusNoContent)
	case r.Method == http.MethodDelete:
		delete(f.v1, key)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (s *fakeSecret) versionJSON(n int) map[string]any {
	v := s.versions[n]
	del := ""
	if !v.deleted.IsZero() {
		del = v.deleted.Format(time.RFC3339Nano)
	}
	return map[string]any{"version": n, "created_time": v.created.Format(time.RFC3339Nano), "deletion_time": del, "destroyed": false, "custom_metadata": s.custom}
}

func (f *fakeKV) serveV2(w http.ResponseWriter, r *http.Request, kind, key string, body map[string]any, list bool) {
	now := time.Now().UTC()
	sec := f.v2[key]
	switch {
	case kind == "metadata" && list:
		paths := make([]string, 0, len(f.v2))
		for p := range f.v2 {
			paths = append(paths, p)
		}
		keys := listKeys(paths, key)
		if len(keys) == 0 {
			notFound(w)
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"keys": keys}})
	case kind == "data" && r.Method == http.MethodPost:
		data, _ := body["data"].(map[string]any)
		current := 0
		if sec != nil {
			current = sec.current
		}
		if opts, ok := body["options"].(map[string]any); ok {
			if cas, ok := opts["cas"].(float64); ok && int(cas) != current {
				writeJSON(w, 400, map[string]any{"errors": []string{"check-and-set parameter did not match the current version"}})
				return
			}
		}
		if sec == nil {
			sec = &fakeSecret{versions: map[int]*fakeVersion{}, created: now}
			f.v2[key] = sec
		}
		sec.current++
		sec.updated = now
		sec.versions[sec.current] = &fakeVersion{data: data, created: now}
		writeJSON(w, 200, map[string]any{"data": sec.versionJSON(sec.current)})
	case kind == "data" && r.Method == http.MethodGet:
		n := 0
		if sec != nil {
			n = sec.current
			if q := r.URL.Query().Get("version"); q != "" {
				n, _ = strconv.Atoi(q)
			}
		}
		if sec == nil || sec.versions[n] == nil {
			notFound(w)
			return
		}
		if !sec.versions[n].deleted.IsZero() {
			writeJSON(w, 404, map[string]any{"data": map[string]any{"data": nil, "metadata": sec.versionJSON(n)}})
			return
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{"data": sec.versions[n].data, "metadata": sec.versionJSON(n)}})
	case kind == "data" && r.Method == http.MethodDelete:
		if sec != nil {
			sec.versions[sec.current].deleted = now
		}
		w.WriteHeader(http.StatusNoContent)
	case kind == "delete" && r.Method == http.MethodPost:
		if sec != nil {
			vs, _ := body["versions"].([]any)
			for _, v := range vs {
				if fv := sec.versions[int(v.(float64))]; fv != nil {
					fv.deleted = now
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case kind == "metadata" && r.Method == http.MethodGet:
		if sec == nil {
			notFound(w)
			return
		}
		versions := map[string]any{}
		for n := range sec.versions {
			versions[strconv.Itoa(n)] = sec.versionJSON(n)
		}
		writeJSON(w, 200, map[string]any{"data": map[string]any{
			"current_version": sec.current, "created_time": sec.created.Format(time.RFC3339Nano),
			"updated_time": sec.updated.Format(time.RFC3339Nano), "custom_metadata": sec.custom, "versions": versions,
			"max_versions": 0, "cas_required": false, "delete_version_after": "0s", "oldest_version": 0,
		}})
	case kind == "metadata" && r.Method == http.MethodPost:
		if sec != nil {
			if cm, ok := body["custom_metadata"].(map[string]any); ok {
				sec.custom = map[string]string{}
				for k, v := range cm {
					sec.custom[k], _ = v.(string)
				}
			}
		}
		w.WriteHeader(http.StatusNoContent)
	case kind == "metadata" && r.Method == http.MethodDelete:
		delete(f.v2, key)
		w.WriteHeader(http.StatusNoContent)
	default:
		notFound(w)
	}
}
