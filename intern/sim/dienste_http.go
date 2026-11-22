package sim

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/blocksberghexhex/badbot/intern/lauscher"
	"github.com/blocksberghexhex/badbot/intern/puffer"
)

// HTTPDienst bedient einen eigenen Port mit einer HTTP-Simulation ohne TLS
// (Docker-API, Elasticsearch).
func HTTPDienst(ln net.Listener, h http.Handler) *http.Server {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       10 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go srv.Serve(ln)
	return srv
}

// grundprobe: was jede HTTP-Simulation festhaelt, plus der gekuerzte Body.
func grundprobe(r *http.Request, bodyZeichen int) ([]byte, []puffer.Merkmal) {
	probe := []puffer.Merkmal{
		Text("methode", r.Method, 16),
		Text("pfad", ohnePasswort(r.URL), 200),
		Text("ua", r.UserAgent(), 200),
		Text("kopf", kopfnamen(r.Header), 300),
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 16<<10))
	if len(body) > 0 {
		probe = append(probe, Text("body", string(body), bodyZeichen))
	}
	return body, probe
}

func melden(melde func(puffer.Beobachtung), simulation string, port int32, r *http.Request, probe []puffer.Merkmal) {
	if q := lauscher.Gegenstelle(addr(r.RemoteAddr)); q.IsValid() {
		melde(puffer.Beobachtung{Quelle: q, Simulation: simulation, Port: port, Zeit: time.Now(), Probe: probe})
	}
}

func jsonAntwort(rw http.ResponseWriter, r *http.Request, status int, inhalt string) {
	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(status)
	if r.Method != http.MethodHead {
		io.WriteString(rw, inhalt)
	}
}

func jsonText(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

// ---------------------------------------------------------------------------
// Docker-API

// Docker spielt eine offene Docker-API (Port 2375) mit einem Autorisierungs-
// Plugin: Lesen geht und zeigt einen leeren Rechner, jedes Anlegen, Starten
// oder Ausfuehren wird abgewiesen. Ein Container entsteht nie.
type Docker struct {
	Version string // z. B. 20.10.7
	Port    int32
	Melde   func(puffer.Beobachtung)
}

var (
	dockerAPIPraefix = regexp.MustCompile(`^/v1\.\d{1,2}(/|$)`)
	dockerImage      = regexp.MustCompile(`"(?:Image|fromImage)"\s*:\s*"([^"]{1,120})"`)
)

func (d *Docker) api() string {
	if strings.HasPrefix(d.Version, "19.") {
		return "1.40"
	}
	return "1.41"
}

func (d *Docker) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	body, probe := grundprobe(r, 256)
	pfad := dockerAPIPraefix.ReplaceAllString(r.URL.Path, "/")
	lesen := r.Method == http.MethodGet || r.Method == http.MethodHead
	if !lesen {
		// Alles, was schreibt, ist Absicht: Container anlegen, Abbild holen,
		// exec. Abgebildet wird nur, was versucht wurde.
		k := r.Method + " " + kurz(pfad, 80)
		if m := dockerImage.FindSubmatch(body); m != nil {
			k += " " + string(m[1])
		}
		probe = append(probe, Text("kommandos", k, 160))
	}
	melden(d.Melde, "docker", d.Port, r, probe)

	h := rw.Header()
	h.Set("Server", "Docker/"+d.Version+" (linux)")
	h.Set("Api-Version", d.api())
	h.Set("Docker-Experimental", "false")
	h.Set("Ostype", "linux")
	if !lesen {
		jsonAntwort(rw, r, http.StatusForbidden, `{"message":"authorization denied by plugin authz-broker: request denied"}`+"\n")
		return
	}
	switch {
	case pfad == "/_ping":
		h.Set("Content-Type", "text/plain; charset=utf-8")
		rw.WriteHeader(http.StatusOK)
		if r.Method != http.MethodHead {
			io.WriteString(rw, "OK")
		}
	case pfad == "/version":
		jsonAntwort(rw, r, 200, jsonText(map[string]any{
			"Platform": map[string]string{"Name": "Docker Engine - Community"}, "Version": d.Version,
			"ApiVersion": d.api(), "MinAPIVersion": "1.12", "Os": "linux", "Arch": "amd64",
			"KernelVersion": "5.4.0-150-generic", "GoVersion": "go1.13.15"})+"\n")
	case pfad == "/info":
		jsonAntwort(rw, r, 200, jsonText(map[string]any{
			"Containers": 0, "ContainersRunning": 0, "ContainersPaused": 0, "ContainersStopped": 0, "Images": 0,
			"ServerVersion": d.Version, "OperatingSystem": "Ubuntu 20.04.6 LTS", "OSType": "linux",
			"Architecture": "x86_64", "NCPU": 2, "MemTotal": 4110053376, "Driver": "overlay2"})+"\n")
	case pfad == "/containers/json" || pfad == "/images/json" || pfad == "/networks":
		jsonAntwort(rw, r, 200, "[]\n")
	case pfad == "/volumes":
		jsonAntwort(rw, r, 200, `{"Volumes":[],"Warnings":null}`+"\n")
	default:
		jsonAntwort(rw, r, 404, `{"message":"page not found"}`+"\n")
	}
}

// ---------------------------------------------------------------------------
// Elasticsearch

// Elastic spielt einen Elasticsearch-Knoten ohne Indizes (Port 9200). Lesen
// zeigt einen leeren Cluster; Schreiben, Loeschen und Skripte scheitern an
// der Berechtigung. Mitgeschickte Zugangsdaten werden gehasht festgehalten.
type Elastic struct {
	Version string // z. B. 7.10.2
	Port    int32
	Melde   func(puffer.Beobachtung)
}

var elasticLucene = map[string]string{"6.8.23": "7.7.3", "7.10.2": "8.7.0", "7.17.9": "8.11.1"}

const (
	elasticVerboten = `{"error":{"root_cause":[{"type":"security_exception","reason":"action is unauthorized"}],"type":"security_exception","reason":"action is unauthorized"},"status":403}`
	elasticFehlt    = `{"error":{"root_cause":[{"type":"index_not_found_exception","reason":"no such index"}],"type":"index_not_found_exception","reason":"no such index"},"status":404}`
)

func (e *Elastic) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	body, probe := grundprobe(r, 256)
	if name, pw, ok := basisAnmeldung(r); ok {
		probe = append(probe, Anmeldung(name, pw))
	}
	lesen := r.Method == http.MethodGet || r.Method == http.MethodHead
	skript := strings.Contains(string(body), `"script"`) || strings.Contains(strings.ToLower(r.URL.RawQuery), "script")
	if !lesen || skript {
		probe = append(probe, Text("kommandos", r.Method+" "+kurz(r.URL.Path, 100), 120))
	}
	melden(e.Melde, "elasticsearch", e.Port, r, probe)

	rw.Header().Set("X-Elastic-Product", "Elasticsearch")
	p := r.URL.Path
	switch {
	case !lesen || skript:
		jsonAntwort(rw, r, 403, elasticVerboten)
	case p == "/":
		lucene := elasticLucene[e.Version]
		jsonAntwort(rw, r, 200, jsonText(map[string]any{
			"name": "node-1", "cluster_name": "elasticsearch", "cluster_uuid": "Zx3kP1bLQyW0rT8mV5nE2g",
			"version": map[string]any{"number": e.Version, "build_flavor": "default", "build_type": "deb",
				"lucene_version": lucene, "minimum_wire_compatibility_version": "6.8.0",
				"minimum_index_compatibility_version": "6.0.0-beta1"},
			"tagline": "You Know, for Search"})+"\n")
	case strings.HasPrefix(p, "/_cat/"):
		rw.Header().Set("Content-Type", "text/plain; charset=UTF-8")
		rw.WriteHeader(200)
	case p == "/_cluster/health":
		jsonAntwort(rw, r, 200, `{"cluster_name":"elasticsearch","status":"green","timed_out":false,"number_of_nodes":1,"number_of_data_nodes":1,"active_primary_shards":0,"active_shards":0,"relocating_shards":0,"initializing_shards":0,"unassigned_shards":0}`)
	case strings.HasPrefix(p, "/_nodes"):
		jsonAntwort(rw, r, 200, `{"_nodes":{"total":1,"successful":1,"failed":0},"cluster_name":"elasticsearch","nodes":{}}`)
	default:
		jsonAntwort(rw, r, 404, elasticFehlt)
	}
}

// basisAnmeldung liest HTTP-Basic-Zugangsdaten.
func basisAnmeldung(r *http.Request) (string, string, bool) {
	a := r.Header.Get("Authorization")
	roh, ok := strings.CutPrefix(a, "Basic ")
	if !ok {
		return "", "", false
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(roh))
	if err != nil {
		return "", "", false
	}
	name, pw, _ := strings.Cut(string(b), ":")
	return name, pw, true
}
