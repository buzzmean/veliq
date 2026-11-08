package clientservice

import (
	"encoding/base64"
	"github.com/buzzmean/neexitlag/core/browserproxy"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

func validAuthorityPAC(pac string) bool {
	const prefix = "data:application/x-ns-proxy-autoconfig;base64,"
	if len(pac) > 128*1024 || !strings.HasPrefix(pac, prefix) {
		return false
	}
	script, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(pac, prefix))
	if err != nil || !strings.Contains(string(script), "VELIQ_AUTHORITY_V1") {
		return false
	}
	upgraded, err := browserproxy.AvailabilityPAC(pac)
	return err == nil && upgraded == pac
}

// Epoch-specific proxy aliases also separate new activation evidence from a
// previous cached PAC. They do not authorize a request: real socket owner and
// current profile are checked again by the listener and upstream opener.
func authorityPAC(address, epoch string, guards []string, strict bool) (string, error) {
	args, err := browserproxy.ChromeArgumentsGuarded(address, "owner-authority", guards, strict)
	if err != nil {
		return "", err
	}
	const prefix = "--proxy-pac-url=data:application/x-ns-proxy-autoconfig;base64,"
	script, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(args[1], prefix))
	script = []byte(strings.Replace(string(script), "sha256(host)", "sha256('"+epoch+"|'+host)", 1) + "\n// VELIQ_AUTHORITY_V1\n")
	return browserproxy.AvailabilityPAC("data:application/x-ns-proxy-autoconfig;base64," + base64.StdEncoding.EncodeToString(script))
}

var authorityPortPattern = regexp.MustCompile(`\.localhost:([0-9]{1,5})`)

func authorityAddress(pac string) string {
	if !validAuthorityPAC(pac) {
		return ""
	}
	script, _ := base64.StdEncoding.DecodeString(strings.TrimPrefix(pac, "data:application/x-ns-proxy-autoconfig;base64,"))
	match := authorityPortPattern.FindSubmatch(script)
	if len(match) != 2 {
		return ""
	}
	port, err := strconv.ParseUint(string(match[1]), 10, 16)
	if err != nil || port == 0 {
		return ""
	}
	return netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(port)).String()
}
