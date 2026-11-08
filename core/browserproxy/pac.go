package browserproxy

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/buzzmean/neexitlag/core/originpolicy"
)

// PAC is inline: it has no fetch failure that could silently revert to DIRECT.
// Every origin has a cryptographically distinct ProxyServer hostname, so Chrome
// cannot coalesce a protected origin into another origin's DIRECT HTTP/2 tunnel.
// Chrome resolves these synthetic *.localhost proxy names internally to
// loopback. Windows DNS/proxy settings are never modified.
func PAC(port uint16) string { return guardedPAC(port, nil, false) }

// Explicit policy domains and YouTube never get a DIRECT proxy failover.
// Ordinary DIRECT is opened by the service independently of VPS health.
// Recovery switches policy explicitly instead of poisoning Chrome proxy cache.
func guardedPAC(port uint16, extra []string, strict bool) string {
	guard := []string{"chatgpt.com", "openai.com", "oaistatic.com", "oaiusercontent.com", "chat.com", "youtube.com", "youtu.be", "googlevideo.com", "ytimg.com", "youtube-nocookie.com", "ggpht.com"}
	guard = append(guard, extra...)
	raw, _ := json.Marshal(guard)
	prefix := fmt.Sprintf("var protectedSuffixes=%s; var strictProxy=%t;\n", raw, strict)
	return prefix + fmt.Sprintf(`function sha256(s) {
 var k=[1116352408,1899447441,3049323471,3921009573,961987163,1508970993,2453635748,2870763221,3624381080,310598401,607225278,1426881987,1925078388,2162078206,2614888103,3248222580,3835390401,4022224774,264347078,604807628,770255983,1249150122,1555081692,1996064986,2554220882,2821834349,2952996808,3210313671,3336571891,3584528711,113926993,338241895,666307205,773529912,1294757372,1396182291,1695183700,1986661051,2177026350,2456956037,2730485921,2820302411,3259730800,3345764771,3516065817,3600352804,4094571909,275423344,430227734,506948616,659060556,883997877,958139571,1322822218,1537002063,1747873779,1955562222,2024104815,2227730452,2361852424,2428436474,2756734187,3204031479,3329325298];
 var h=[1779033703,3144134277,1013904242,2773480762,1359893119,2600822924,528734635,1541459225], a=[],i,j,n=s.length*8;
 for(i=0;i<s.length;i++)a.push(s.charCodeAt(i));a.push(128);while(a.length%%64!==56)a.push(0);for(i=7;i>=0;i--)a.push(i<4?(n>>>(i*8))&255:0);
 function rr(x,n){return (x>>>n)|(x<<(32-n));}
 for(i=0;i<a.length;i+=64){var w=[];for(j=0;j<16;j++)w[j]=(a[i+4*j]<<24)|(a[i+4*j+1]<<16)|(a[i+4*j+2]<<8)|a[i+4*j+3];for(j=16;j<64;j++){var u=w[j-15],v=w[j-2];w[j]=(w[j-16]+(rr(u,7)^rr(u,18)^(u>>>3))+w[j-7]+(rr(v,17)^rr(v,19)^(v>>>10)))|0;}
 var x=h.slice(0);for(j=0;j<64;j++){var t=(x[7]+(rr(x[4],6)^rr(x[4],11)^rr(x[4],25))+((x[4]&x[5])^(~x[4]&x[6]))+k[j]+w[j])|0;var z=((rr(x[0],2)^rr(x[0],13)^rr(x[0],22))+((x[0]&x[1])^(x[0]&x[2])^(x[1]&x[2])))|0;x=[(t+z)|0,x[0],x[1],x[2],(x[3]+t)|0,x[4],x[5],x[6]];}for(j=0;j<8;j++)h[j]=(h[j]+x[j])|0;}
 var out='';for(i=0;i<8;i++)out+=('00000000'+(h[i]>>>0).toString(16)).slice(-8);return out;
}
function FindProxyForURL(url,host) {
 host=host.toLowerCase().replace(/\.$/,'');
 var h=sha256(host);return 'PROXY '+h.slice(0,32)+'.'+h.slice(32)+'.localhost:%d';
}`, port)
}
func ChromeArguments(address, profile string) ([]string, error) {
	return ChromeArgumentsGuarded(address, profile, nil, false)
}
func ChromeArgumentsGuarded(address, profile string, extra []string, strict bool) ([]string, error) {
	host, p, e := net.SplitHostPort(address)
	if e != nil || host != "127.0.0.1" || profile == "" {
		return nil, fmt.Errorf("loopback transport and persistent Chrome profile required")
	}
	port, e := strconv.ParseUint(p, 10, 16)
	if e != nil || port == 0 {
		return nil, fmt.Errorf("invalid loopback port")
	}
	pac := "data:application/x-ns-proxy-autoconfig;base64," + base64.StdEncoding.EncodeToString([]byte(guardedPAC(uint16(port), extra, strict)))
	return []string{"--user-data-dir=" + profile, "--proxy-pac-url=" + pac, "--proxy-bypass-list=<-loopback>", "--no-first-run"}, nil
}

// Recovery is a separate owned policy, never a DIRECT alternative in the online
// proxy chain. Otherwise Chrome caches the failed proxy for ordinary origins and
// keeps using DIRECT after restart, sending opaque native TLS into relay policy.
func ChromeRecoveryArguments(address, profile string, extra []string, strict bool) ([]string, error) {
	args, err := ChromeArgumentsGuarded(address, profile, extra, strict)
	if err != nil {
		return nil, err
	}
	const prefix = "--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,"
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(args[1], prefix))
	if err != nil {
		return nil, err
	}
	raw = append(raw, []byte(`
FindProxyForURL=(function(online){return function(url,host){host=host.toLowerCase().replace(/\.$/,'');if(strictProxy)return online(url,host);for(var i=0;i<protectedSuffixes.length;i++){var d=protectedSuffixes[i].toLowerCase().replace(/\.$/,'');if(host===d||host.slice(-(d.length+1))==='.'+d)return online(url,host);}return 'DIRECT';};})(FindProxyForURL);`)...)
	args[1] = prefix + base64.StdEncoding.EncodeToString(raw)
	return args, nil
}

// A separately supervised, owner-scoped CONNECT process is the ordinary-origin
// recovery path. Never add a bare DIRECT alternative: that bypasses attribution
// and leaves Chrome's bad-proxy cache skipping the healthy origin planner.
func ChromeArgumentsWithRecovery(address, profile string, extra []string, strict bool, recovery string) ([]string, error) {
	args, err := ChromeArgumentsGuarded(address, profile, extra, strict)
	if err != nil {
		return nil, err
	}
	endpoint, err := netip.ParseAddrPort(recovery)
	if err != nil || !endpoint.Addr().Is4() || !endpoint.Addr().IsLoopback() || endpoint.Port() == 0 || recovery == address {
		return nil, fmt.Errorf("distinct IPv4 loopback recovery endpoint required")
	}
	const prefix = "--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,"
	script, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(args[1], prefix))
	if err != nil {
		return nil, err
	}
	script = append(script, []byte(fmt.Sprintf(`
FindProxyForURL=(function(primary){return function(url,host){host=host.toLowerCase().replace(/\.$/,'');var p=primary(url,host);if(strictProxy)return p;for(var i=0;i<protectedSuffixes.length;i++){var d=protectedSuffixes[i].toLowerCase().replace(/\.$/,'');if(host===d||host.slice(-(d.length+1))==='.'+d)return p;}return p+'; '+p.slice(0,p.lastIndexOf(':')+1)+'%d';};})(FindProxyForURL);`, endpoint.Port()))...)
	args[1] = prefix + base64.StdEncoding.EncodeToString(script)
	return args, nil
}

// Availability fallback applies only to ordinary origins. Protected registry
// floors, profile guard domains and strict profiles remain fail-closed even when
// both proxy infrastructure and native capture are absent. Existing V1 owner
// journals are upgraded without duplicating wrappers; browser uptake is separate.
func AvailabilityPAC(pac string) (string, error) {
	const prefix = "data:application/x-ns-proxy-autoconfig;base64,"
	if !strings.HasPrefix(pac, prefix) {
		return "", fmt.Errorf("inline PAC required")
	}
	script, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pac, prefix))
	if err != nil || len(script) > 256*1024 {
		return "", fmt.Errorf("bounded PAC required")
	}
	if !strings.Contains(string(script), "var protectedSuffixes=") || !strings.Contains(string(script), "var strictProxy=") {
		return "", fmt.Errorf("known guarded PAC metadata required")
	}
	if !strings.Contains(string(script), "VELIQ_AVAILABILITY_V2") {
		floors := []string{}
		for _, rule := range originpolicy.Bundled().Rules {
			if rule.Kind == "RELAY" {
				floors = append(floors, rule.Suffixes...)
			}
		}
		raw, _ := json.Marshal(floors)
		script = append(script, []byte(fmt.Sprintf(`
// VELIQ_AVAILABILITY_V2
var availabilityFloorSuffixes=%s;
FindProxyForURL=(function(route){return function(url,host){
 host=host.toLowerCase().replace(/\.$/,'');
 var p=route(url,host),guard=strictProxy,domains=protectedSuffixes.concat(availabilityFloorSuffixes);
 for(var i=0;i<domains.length;i++){var d=domains[i].toLowerCase().replace(/\.$/,'');if(host===d||host.slice(-(d.length+1))==='.'+d){guard=true;break;}}
 if(guard){
  var parts=p.split(';'),safe=[];
  for(var j=0;j<parts.length;j++){var item=parts[j].replace(/^\s+|\s+$/g,'');if(item&&!/^DIRECT$/i.test(item))safe.push(item);}
  return safe.length?safe.join('; '):'PROXY fail-closed.neexitlag.invalid:9';
 }
 return /(^|;\s*)DIRECT\s*$/.test(p)?p:p+'; DIRECT';
};})(FindProxyForURL);`, raw))...)
	}
	if len(script) > 256*1024 {
		return "", fmt.Errorf("bounded PAC required")
	}
	return prefix + base64.StdEncoding.EncodeToString(script), nil
}
