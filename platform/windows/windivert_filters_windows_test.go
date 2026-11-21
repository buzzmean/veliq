//go:build windows

package windowsplatform

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func loadPinnedFilterDLL(t *testing.T) *windows.DLL {
	t.Helper()
	dir := os.Getenv("NEEXITLAG_TEST_DRIVER_DIR")
	if dir == "" {
		if os.Getenv("NEEXITLAG_REQUIRE_FILTER_COMPILER") == "1" {
			t.Fatal("WINDIVERT_FILTER_DLL_REQUIRED; build gate cannot skip")
		}
		t.Skip("pinned WinDivert DLL required; no filter compilation proof")
	}
	path, err := filepath.Abs(filepath.Join(dir, "WinDivert.dll"))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%x", sha256.Sum256(raw)) != "c1e060ee19444a259b2162f8af0f3fe8c4428a1c6f694dce20de194ac8d7d9a2" {
		t.Fatal("unapproved fixture DLL")
	}
	// No WinDivertOpen/driver access; library dependencies use only safe paths.
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_DEFAULT_DIRS)
	if err != nil {
		t.Fatal(err)
	}
	dll := &windows.DLL{Name: path, Handle: handle}
	t.Cleanup(func() { dll.Release() })
	return dll
}

func TestServiceFiltersCompileWithActualWinDivert(t *testing.T) {
	dll := loadPinnedFilterDLL(t)
	compile, err := dll.FindProc("WinDivertHelperCompileFilter")
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []bool{false, true} {
		for _, port := range []uint16{1, 3260, 50165, 62841, 65535} {
			for _, spec := range serviceWinDivertFilters(port, fixture) {
				t.Run(fmt.Sprintf("%s/layer=%d/port=%d/fixture=%v", spec.name, spec.layer, port, fixture), func(t *testing.T) {
					if err := compileDivertFilter(compile, spec.text, spec.layer); err != nil {
						t.Fatal(err)
					}
					t.Logf("compiled length=%d", len(spec.text))
				})
			}
		}
	}
}

func TestWinDivertCompilerRejectsLegacyGroupedNot(t *testing.T) {
	dll := loadPinnedFilterDLL(t)
	compile, err := dll.FindProc("WinDivertHelperCompileFilter")
	if err != nil {
		t.Fatal(err)
	}
	private := func(field string) string {
		return fmt.Sprintf("((%s >= 10.0.0.0 and %s <= 10.255.255.255) or (%s >= 172.16.0.0 and %s <= 172.31.255.255) or (%s >= 192.168.0.0 and %s <= 192.168.255.255))", field, field, field, field, field, field)
	}
	legacy := "ip and tcp and !impostor and ((outbound and !loopback) or (inbound and (!loopback or tcp.DstPort == 62841))) and not ((outbound and tcp.DstPort == 3260 and " + private("ip.DstAddr") + ") or (inbound and tcp.SrcPort == 3260 and " + private("ip.SrcAddr") + "))"
	err = compileDivertFilter(compile, legacy, 0)
	want := fmt.Sprintf("offset=%d ", strings.Index(legacy, "not (")+4)
	if err == nil || !strings.Contains(err.Error(), want) || !strings.Contains(err.Error(), "parse error") {
		t.Fatalf("expected exact grouped-NOT parser offset %s, got %v", want, err)
	}
	t.Log(err)
	// The real runtime entry point must stop before any kernel call. Leaving
	// open nil makes an accidental attempt to open an invalid filter fail.
	d := &divertDLL{compile: compile}
	if _, err := d.openHandle(legacy, 0, 0); err == nil || !strings.Contains(err.Error(), want) {
		t.Fatalf("runtime did not preserve compiler failure: %v", err)
	}
	// Even a tiny grouped NOT is invalid. Length/instruction limits are not
	// the cause of e3dc65c; the exact former full expression is checked above.
	if err := compileDivertFilter(compile, "not (outbound)", 0); err == nil || !strings.Contains(err.Error(), "offset=4 ") {
		t.Fatalf("grouped NOT unexpectedly valid: %v", err)
	}
	if err := compileDivertFilter(compile, "processId == 1", 0); err == nil || !strings.Contains(err.Error(), "bad token for layer") {
		t.Fatalf("wrong-layer compiler error lost: %v", err)
	}
}

func TestWinDivertCompilerReportsComplexityLimits(t *testing.T) {
	dll := loadPinnedFilterDLL(t)
	compile, err := dll.FindProc("WinDivertHelperCompileFilter")
	if err != nil {
		t.Fatal(err)
	}
	// Text length alone is not the limit: whitespace is ignored by the parser.
	if err := compileDivertFilter(compile, strings.Repeat(" ", 4096)+"tcp", 0); err != nil {
		t.Fatal(err)
	}
	deep := strings.Repeat("(", 600) + "tcp" + strings.Repeat(")", 600)
	// The pinned 2.2.2 parser overwrites its internal depth error while
	// unwinding: its public API reports parse error at opening bracket 341.
	if err := compileDivertFilter(compile, deep, 0); err == nil || !strings.Contains(err.Error(), "parse error") || !strings.Contains(err.Error(), "offset=341 ") {
		t.Fatalf("parser depth limit not reported: %v", err)
	}
	var terms []string
	for port := 1; port <= 300; port++ {
		terms = append(terms, fmt.Sprintf("tcp.SrcPort == %d", port))
	}
	if err := compileDivertFilter(compile, strings.Join(terms, " or "), 0); err == nil || !strings.Contains(err.Error(), "too long") {
		t.Fatalf("instruction limit not reported: %v", err)
	}
}
