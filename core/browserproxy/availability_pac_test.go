package browserproxy

import (
	"encoding/base64"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"

	"github.com/buzzmean/neexitlag/core/originpolicy"
)

func executeAvailabilityPAC(t *testing.T, pac string, names []string) []string {
	t.Helper()
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node required to execute real PAC JavaScript")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pac, "data:application/x-ns-proxy-autoconfig;base64,"))
	if err != nil {
		t.Fatal(err)
	}
	input, _ := json.Marshal(map[string]any{"pac": string(raw), "names": names})
	cmd := exec.Command(node, "-e", `let d='';process.stdin.on('data',v=>d+=v);process.stdin.on('end',()=>{let x=JSON.parse(d),c={};require('vm').runInNewContext(x.pac,c,{timeout:100});process.stdout.write(JSON.stringify(x.names.map(n=>c.FindProxyForURL('https://'+n,n))));});`)
	cmd.Stdin = strings.NewReader(string(input))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatal("PAC execution failed", err)
	}
	var routes []string
	if json.Unmarshal(out, &routes) != nil || len(routes) != len(names) {
		t.Fatal("PAC results incomplete")
	}
	return routes
}

func TestAvailabilityPACDoesNotBypassProtectedFloor(t *testing.T) {
	names := []string{"CHATGPT.COM.", "api.openai.com", "www.youtube.com", "a.googlevideo.com", "private.example", "sub.private.example"}
	for _, rule := range originpolicy.Bundled().Rules {
		if rule.Kind == "RELAY" {
			for _, host := range rule.Suffixes {
				names = append(names, host, "sub."+host)
			}
		}
	}
	names = append(names, "ordinary.example", "chatgpt.com.evil.example", "notopenai.com")
	for _, strict := range []bool{false, true} {
		args, err := ChromeArgumentsWithRecovery("127.0.0.1:1234", "fixture", []string{"private.example"}, strict, "127.0.0.1:1235")
		if err != nil {
			t.Fatal(err)
		}
		pac, err := AvailabilityPAC(strings.TrimPrefix(args[1], "--proxy-pac-url="))
		if err != nil {
			t.Fatal(err)
		}
		again, err := AvailabilityPAC(pac)
		if err != nil || again != pac {
			t.Fatal("not idempotent")
		}
		routes := executeAvailabilityPAC(t, pac, names)
		for i, route := range routes {
			guarded := strict || i < len(names)-3
			direct := false
			for _, item := range strings.Split(route, ";") {
				if strings.EqualFold(strings.TrimSpace(item), "DIRECT") {
					direct = true
				}
			}
			if guarded && direct {
				t.Fatalf("protected/strict origin acquired DIRECT: %s", names[i])
			}
			if !guarded && (!strings.HasSuffix(route, "; DIRECT") || !strings.Contains(route, ":1235")) {
				t.Fatal("ordinary recovery/availability missing", names[i])
			}
		}
	}
}

func TestAvailabilityPACUpgradesV1AndClosedRecoveryWithoutDirect(t *testing.T) {
	const prefix = "data:application/x-ns-proxy-autoconfig;base64,"
	args, err := ChromeRecoveryArguments("127.0.0.1:1234", "fixture", nil, false)
	if err != nil {
		t.Fatal(err)
	}
	script, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(args[1], "--proxy-pac-url="+prefix))
	if err != nil {
		t.Fatal(err)
	}
	// Historical all-host availability framing from the owner journal. A new
	// relay-floor family may already return only DIRECT in this recovery PAC.
	script = append(script, []byte(`
// VELIQ_AVAILABILITY_V1
FindProxyForURL=(function(route){return function(url,host){var p=route(url,host);return /(^|;\s*)DIRECT\s*$/.test(p)?p:p+'; DIRECT';};})(FindProxyForURL);`)...)
	pac, err := AvailabilityPAC(prefix + base64.StdEncoding.EncodeToString(script))
	if err != nil {
		t.Fatal(err)
	}
	names := []string{"api.openai.com", "api.anthropic.com", "ordinary.example"}
	routes := executeAvailabilityPAC(t, pac, names)
	for i := 0; i < 2; i++ {
		for _, item := range strings.Split(routes[i], ";") {
			if strings.EqualFold(strings.TrimSpace(item), "DIRECT") {
				t.Fatal("legacy DIRECT survived security floor upgrade", names[i])
			}
		}
	}
	if routes[1] != "PROXY fail-closed.neexitlag.invalid:9" || routes[2] != "DIRECT" {
		t.Fatal("legacy recovery fail-closed/ordinary mismatch")
	}
	again, err := AvailabilityPAC(pac)
	if err != nil || again != pac {
		t.Fatal("upgraded PAC not idempotent")
	}
}

func TestAvailabilityPACRejectsUnknownGuardMetadata(t *testing.T) {
	for _, pac := range []string{"https://example.test/pac", "data:application/x-ns-proxy-autoconfig;base64,?", "data:application/x-ns-proxy-autoconfig;base64," + base64.StdEncoding.EncodeToString([]byte("function FindProxyForURL(){return 'DIRECT';}"))} {
		if _, err := AvailabilityPAC(pac); err == nil {
			t.Fatal("unguarded/malformed PAC accepted")
		}
	}
}
