package controlplane

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/buzzmean/veliq/core/clubhealth"
	"github.com/buzzmean/veliq/core/security"
)

func persistentClubLinkFixture(pc, protocol, event string) clubhealth.Diagnostic {
	e := persistentFixtureBatch(pc).Events[0]
	e.Version, e.Source, e.ServicePID = "0.3.792", "095c8ac8", 44
	e.Component, e.Observer, e.Code, e.State = "CLUB_LINK", "PASSIVE_TCP_TABLE", event, "failed"
	e.NativeCode, e.EventID = 0, 0
	e.PID, e.Birth, e.App, e.ProcessVerified = 24, 123456, "langameservice.exe", true
	e.Incident = strings.Repeat("c", 32)
	e.ClubLink = clubhealth.ClubLink{Kind: "LANGAME", LinkID: e.Incident, PeerID: strings.Repeat("d", 32), Protocol: protocol,
		Event: event, Previous: "ESTABLISHED", Current: "ABSENT", LastEstablishedAt: e.At.Add(-4 * time.Second)}
	if event == "CONNECTION_RESTORED" {
		e.State = "recovered"
		e.ClubLink.Previous, e.ClubLink.Current, e.ClubLink.LastEstablishedAt = "ABSENT", "ESTABLISHED", e.At
	}
	return e
}

func diagnosticRequest(t *testing.T, a *API, q clubhealth.PersistentRequest) (int, clubhealth.Receipt) {
	t.Helper()
	raw, err := json.Marshal(q)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	a.Handler().ServeHTTP(w, httptest.NewRequest("POST", clubhealth.PersistentEndpoint, bytes.NewReader(raw)))
	var receipt clubhealth.Receipt
	_ = json.Unmarshal(w.Body.Bytes(), &receipt)
	return w.Code, receipt
}

func assertClubLinkStored(t *testing.T, s *Store, device string, expected clubhealth.Diagnostic, count int) {
	t.Helper()
	var raw []byte
	if err := s.DB.QueryRow(context.Background(), `SELECT summary FROM club_health_persistent_events WHERE device_id=$1 AND event_id=$2`, device, expected.ID).Scan(&raw); err != nil {
		t.Fatal(err)
	}
	var stored clubhealth.Diagnostic
	if json.Unmarshal(raw, &stored) != nil || !reflect.DeepEqual(stored, expected) || stored.Operation != "" {
		t.Fatal("storage did not retain the canonical typed fact")
	}
	var records int
	if err := s.DB.QueryRow(context.Background(), `SELECT count(*) FROM club_health_persistent_events WHERE device_id=$1`, device).Scan(&records); err != nil || records != count {
		t.Fatal("different representations duplicated an event", err, records)
	}
}

func TestClubLinkPersistentProofCanonicalCopiesAndImmutableReplay(t *testing.T) {
	a, s, _ := accountAPI(t, true)
	_, device, key := persistentDeviceFixture(t, s, "PC13")
	typed := persistentClubLinkFixture("PC13", "TCP6", "CONNECTION_LOST")
	both, ok := typed.WithClubLinkShadow()
	if !ok {
		t.Fatal("fixture")
	}
	downlevel := both
	downlevel.ClubLink = clubhealth.ClubLink{}
	for _, e := range []clubhealth.Diagnostic{downlevel, both, typed, downlevel} {
		b := clubhealth.Batch{Protocol: 1, Events: []clubhealth.Diagnostic{e}}
		proof, err := security.NewProof(device, b.Audience(), key, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		q := clubhealth.PersistentRequest{Batch: b, Proof: proof}
		if status, receipt := diagnosticRequest(t, a, q); status != 200 || !receipt.Accepts(b) {
			t.Fatal("original wire proof or receipt rejected", status)
		}
		assertClubLinkStored(t, s, device, typed, 1)
	}
	// A direct store caller shares the Events slice. Storage normalization must
	// not hydrate or strip fields in that caller's already verified wire batch.
	b := clubhealth.Batch{Protocol: 1, Events: []clubhealth.Diagnostic{downlevel}}
	proof, _ := security.NewProof(device, b.Audience(), key, time.Now())
	q := clubhealth.PersistentRequest{Batch: b, Proof: proof}
	before, _ := json.Marshal(q)
	if err := s.RecordPersistentDiagnostics(context.Background(), q); err != nil {
		t.Fatal(err)
	}
	after, _ := json.Marshal(q)
	if !bytes.Equal(before, after) || !q.Batch.Events[0].ClubLink.IsZero() || q.Batch.Audience() != q.Proof.RelayID {
		t.Fatal("storage mutated a caller's wire batch or proof")
	}
	// A signature over the canonical projection does not authenticate shadow
	// wire bytes, even though both describe the same intended observation.
	canonicalBatch := clubhealth.Batch{Protocol: 1, Events: []clubhealth.Diagnostic{typed}}
	q.Proof, _ = security.NewProof(device, canonicalBatch.Audience(), key, time.Now())
	if status, _ := diagnosticRequest(t, a, q); status != 400 {
		t.Fatal("canonical digest accepted for a different wire representation", status)
	}
	q.Proof, _ = security.NewProof(device, b.Audience(), key, time.Now())
	q.Proof.Signature = strings.Repeat("A", len(q.Proof.Signature))
	if status, _ := diagnosticRequest(t, a, q); status != 401 {
		t.Fatal("invalid signature reached storage", status)
	}
	changed := typed
	changed.ClubLink.PeerID = strings.Repeat("f", 32)
	changed, _ = changed.WithClubLinkShadow()
	q.Batch.Events = []clubhealth.Diagnostic{changed}
	q.Proof, _ = security.NewProof(device, q.Batch.Audience(), key, time.Now())
	if status, _ := diagnosticRequest(t, a, q); status != 409 {
		t.Fatal("signed retry reassigned immutable event to a different peer", status)
	}
	assertClubLinkStored(t, s, device, typed, 1)
	changed = both
	changed.ClubLink.PeerID = strings.Repeat("f", 32)
	q.Batch.Events = []clubhealth.Diagnostic{changed}
	q.Proof, _ = security.NewProof(device, q.Batch.Audience(), key, time.Now())
	if status, _ := diagnosticRequest(t, a, q); status != 400 {
		t.Fatal("contradictory typed/shadow pair accepted", status)
	}
}

const downlevel762Commit = "0faa9aab69335c1b0024da32c880d21fa42ed6e5"

// This helper is compiled with the unmodified core packages at the official
// 762 source commit, not a duplicate old DTO or a new-code marshaler. Its only
// network destination is this test's loopback httptest server.
const downlevel762Helper = `package main
import (
 "bytes"
 "crypto/ed25519"
 "encoding/json"
 "fmt"
 "io"
 "net/http"
 "os"
 "path/filepath"
 "time"
 "github.com/buzzmean/veliq/core/clubhealth"
 "github.com/buzzmean/veliq/core/security"
)
func run() error {
 var in struct { Journal json.RawMessage; Device string; Seed []byte; URL string; Now time.Time; Reporter clubhealth.Reporter }
 if err:=json.NewDecoder(os.Stdin).Decode(&in);err!=nil{return err}
 if len(in.Seed)!=ed25519.SeedSize{return fmt.Errorf("invalid fixture seed")}
 dir,err:=os.MkdirTemp("","veliq-762-journal-");if err!=nil{return err};defer os.RemoveAll(dir)
 path:=filepath.Join(dir,"journal.json")
 write:=func(b []byte)error{return os.WriteFile(path,b,0600)}
 if err=write(in.Journal);err!=nil{return err}
 journal:=clubhealth.LoadJournal(path,in.Device,in.Now)
 if err=journal.Save(write);err!=nil{return err}
 journal=clubhealth.LoadJournal(path,in.Device,in.Now)
 before,_:=json.Marshal(journal)
 batch:=journal.Batch();batch.Reporter=&in.Reporter
 if err=batch.Validate(time.Now());err!=nil{return err}
 proof,err:=security.NewProof(in.Device,batch.Audience(),ed25519.NewKeyFromSeed(in.Seed),time.Now());if err!=nil{return err}
 request:=clubhealth.PersistentRequest{Batch:batch,Proof:proof}
 raw,err:=json.Marshal(request);if err!=nil{return err}
 client:=http.Client{Timeout:5*time.Second}
 response,err:=client.Post(in.URL,"application/json",bytes.NewReader(raw));if err!=nil{return err};defer response.Body.Close()
 if response.StatusCode!=200{return fmt.Errorf("ingest status %d",response.StatusCode)}
 var receipt clubhealth.Receipt
 if err=json.NewDecoder(io.LimitReader(response.Body,65536)).Decode(&receipt);err!=nil{return err}
 if !receipt.Accepts(batch)||!journal.Ack(batch,receipt){return fmt.Errorf("original 762 ACK rejected")}
 if err=journal.Save(write);err!=nil{return err}
 journal=clubhealth.LoadJournal(path,in.Device,in.Now)
 return json.NewEncoder(os.Stdout).Encode(struct {Before json.RawMessage; After clubhealth.Journal; Request clubhealth.PersistentRequest; Receipt clubhealth.Receipt}{before,journal,request,receipt})
}
func main(){if err:=run();err!=nil{fmt.Fprintln(os.Stderr,err);os.Exit(1)}}
`

func buildDownlevel762Codec(t *testing.T) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root, err := exec.CommandContext(ctx, "git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatal("locate frozen source repository", err)
	}
	cmd := exec.CommandContext(ctx, "git", "archive", "--format=tar", downlevel762Commit, "core", "go.mod", "go.sum")
	cmd.Dir = strings.TrimSpace(string(root))
	cmd.Env = append(os.Environ(), "GIT_NO_REPLACE_OBJECTS=1", "GIT_NO_LAZY_FETCH=1")
	raw, err := cmd.Output()
	if err != nil || len(raw) > 64<<20 {
		t.Fatal("exact 762 source must already be available locally", err)
	}
	dir := t.TempDir()
	archive := tar.NewReader(bytes.NewReader(raw))
	for {
		header, err := archive.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag == tar.TypeXGlobalHeader && header.PAXRecords["comment"] == downlevel762Commit {
			continue // git archive records the pinned commit in a global PAX header.
		}
		name := filepath.Clean(header.Name)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			t.Fatal("invalid source path")
		}
		path := filepath.Join(dir, name)
		if header.Typeflag == tar.TypeDir {
			if err := os.MkdirAll(path, 0700); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if header.Typeflag != tar.TypeReg || header.Size > 4<<20 {
			t.Fatal("unexpected source entry")
		}
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(io.LimitReader(archive, 4<<20+1))
		if err != nil || len(content) > 4<<20 {
			t.Fatal("source bound", err)
		}
		if err = os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "codec.go"), []byte(downlevel762Helper), 0600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "codec")
	goBinary := filepath.Join(runtime.GOROOT(), "bin", "go")
	if runtime.GOOS == "windows" {
		binary += ".exe"
		goBinary += ".exe"
	}
	cmd = exec.CommandContext(ctx, goBinary, "build", "-mod=readonly", "-o", binary, "codec.go")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOPROXY=off", "GOWORK=off")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build unchanged 762 core: %v %s", err, output)
	}
	return binary
}

func TestClubLinkActual762JournalProofIngestAndACK(t *testing.T) {
	if os.Getenv("VELIQ_TEST_DOWNLEVEL_762") != "1" {
		t.Skip("set VELIQ_TEST_DOWNLEVEL_762=1 with exact 762 source and isolated PostgreSQL")
	}
	// Require the DB before compiling anything; a skipped PG fixture must not
	// accidentally look like a successful compatibility acceptance.
	if os.Getenv("VELIQ_TEST_DATABASE_URL") == "" {
		t.Fatal("isolated PostgreSQL is required for the actual 762 acceptance")
	}
	binary := buildDownlevel762Codec(t)
	for _, protocol := range []string{"TCP4", "TCP6"} {
		for _, event := range []string{"CONNECTION_LOST", "CONNECTION_RESTORED"} {
			t.Run(protocol+"/"+event, func(t *testing.T) {
				a, s, _ := accountAPI(t, true)
				_, device, key := persistentDeviceFixture(t, s, "PC13")
				typed := persistentClubLinkFixture("PC13", protocol, event)
				both, ok := typed.WithClubLinkShadow()
				if !ok {
					t.Fatal("fixture")
				}
				acked := persistentFixtureBatch("PC13").Events[0]
				journal := clubhealth.Journal{Format: 1, Device: device, Open: true, Lost: 714991,
					Rows: []clubhealth.JournalRow{{Event: both}, {Event: acked, Acked: true}}}
				rawJournal, _ := json.Marshal(journal)
				server := httptest.NewServer(a.Handler())
				defer server.Close()
				input, _ := json.Marshal(struct {
					Journal  json.RawMessage
					Device   string
					Seed     []byte
					URL      string
					Now      time.Time
					Reporter clubhealth.Reporter
				}{rawJournal, device, key.Seed(), server.URL + clubhealth.PersistentEndpoint, typed.At,
					clubhealth.Reporter{PC: "PC13", Version: "0.3.762", Source: "0faa9aab", Session: strings.Repeat("a", 32), ServicePID: 762}})
				ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
				defer cancel()
				cmd := exec.CommandContext(ctx, binary)
				cmd.Stdin = bytes.NewReader(input)
				var stdout, stderr bytes.Buffer
				cmd.Stdout, cmd.Stderr = &stdout, &stderr
				if err := cmd.Run(); err != nil {
					t.Fatalf("actual 762 codec/upload: %v %s", err, &stderr)
				}
				var result struct {
					Before  clubhealth.Journal
					After   clubhealth.Journal
					Request clubhealth.PersistentRequest
					Receipt clubhealth.Receipt
				}
				if err := json.Unmarshal(stdout.Bytes(), &result); err != nil {
					t.Fatal(err)
				}
				if result.Before.Lost != journal.Lost || result.After.Lost != journal.Lost || len(result.Before.Rows) != 2 ||
					len(result.After.Rows) != 2 || len(result.Request.Batch.Events) != 1 ||
					!result.Before.Rows[0].Event.ClubLink.IsZero() || result.Before.Rows[0].Event.Operation != both.Operation ||
					result.Before.Rows[0].Acked || !result.Before.Rows[1].Acked || !result.After.Rows[0].Acked || !result.After.Rows[1].Acked {
					t.Fatal("old Save/Load lost IDs, metadata, loss accounting or ACK state")
				}
				if result.Before.Rows[0].Event.ID != typed.ID || result.Before.Rows[1].Event != acked ||
					result.Request.Batch.Validate(time.Now()) != nil || !result.Receipt.Accepts(result.Request.Batch) {
					t.Fatal("old signed batch or original digest did not survive")
				}
				pub, err := security.DecodePublicKey(mustDeviceKey(t, s, device))
				if err != nil || result.Request.Proof.Verify(pub, time.Now()) != nil {
					t.Fatal("proof was not produced by the actual 762 signer")
				}
				assertClubLinkStored(t, s, device, typed, 1)
				for _, e := range []clubhealth.Diagnostic{both, typed, result.Request.Batch.Events[0]} {
					batch := clubhealth.Batch{Protocol: 1, Events: []clubhealth.Diagnostic{e}}
					proof, _ := security.NewProof(device, batch.Audience(), key, time.Now())
					if status, receipt := diagnosticRequest(t, a, clubhealth.PersistentRequest{Batch: batch, Proof: proof}); status != 200 || !receipt.Accepts(batch) {
						t.Fatal("typed/downlevel retry conflicted or changed ACK digest", status)
					}
				}
				assertClubLinkStored(t, s, device, typed, 1)
			})
		}
	}
}

func mustDeviceKey(t *testing.T, s *Store, device string) string {
	t.Helper()
	d, err := s.Device(context.Background(), device)
	if err != nil {
		t.Fatal(err)
	}
	return d.PublicKey
}
