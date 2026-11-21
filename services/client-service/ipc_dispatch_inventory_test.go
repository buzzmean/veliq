package clientservice

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// Keep the public dispatcher in sync with both native callers and subhandlers.
// This inspects source, rather than duplicating an IPC allowlist in the test.
func TestIPCDispatcherCoversHandlersAndClientLiterals(t *testing.T) {
	set := token.NewFileSet()
	parsed, err := parser.ParseFile(set, "controller.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	dispatched := map[string]bool{}
	for _, decl := range parsed.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Handle" {
			continue
		}
		// The final method switch is the dispatcher; the earlier switch only sets
		// deferred guard publication, and must not authorize a missing route.
		var main *ast.SwitchStmt
		for _, stmt := range fn.Body.List {
			if sw, ok := stmt.(*ast.SwitchStmt); ok {
				if tag, ok := sw.Tag.(*ast.Ident); ok && tag.Name == "method" {
					main = sw
				}
			}
		}
		if main == nil {
			t.Fatal("IPC dispatcher not found")
		}
		dispatched = ipcCaseStrings(main)
		for _, stmt := range fn.Body.List {
			branch, ok := stmt.(*ast.IfStmt)
			if !ok || len(branch.Body.List) != 1 {
				continue
			}
			if _, ok := branch.Body.List[0].(*ast.ReturnStmt); !ok {
				continue
			}
			eq, ok := branch.Cond.(*ast.BinaryExpr)
			if !ok || eq.Op != token.EQL {
				continue
			}
			name, ok := eq.X.(*ast.Ident)
			if !ok || name.Name != "method" {
				continue
			}
			literal, ok := eq.Y.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				continue
			}
			method, e := strconv.Unquote(literal.Value)
			if e == nil {
				dispatched[method] = true
			}
		}
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(set, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		ast.Inspect(f, func(n ast.Node) bool {
			sw, ok := n.(*ast.SwitchStmt)
			if !ok {
				return true
			}
			tag, ok := sw.Tag.(*ast.Ident)
			if !ok || tag.Name != "method" {
				return true
			}
			for method := range ipcCaseStrings(sw) {
				if !dispatched[method] {
					t.Errorf("%s: handler %q unreachable from Controller.Handle", name, method)
				}
			}
			return true
		})
	}
	ps := regexp.MustCompile(`(?i)\b(?:Invoke-ServiceIPC(?:Once)?|Invoke-IPC)\s+['"]([a-z][a-z0-9_.-]+)['"]`)
	cs := regexp.MustCompile(`\.Call(?:<[^()]*>)?\s*\(\s*"([a-z][a-z0-9_.-]+)"`)
	root := filepath.Join("..", "..")
	calls := 0
	for _, dir := range []string{"tools/windows", "apps/desktop", "apps/desktop-core"} {
		err = filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, e error) error {
			if e != nil {
				return e
			}
			if d.IsDir() {
				if d.Name() == "bin" || d.Name() == "obj" {
					return filepath.SkipDir
				}
				return nil
			}
			re := ps
			if strings.HasSuffix(path, ".cs") {
				re = cs
			} else if !strings.HasSuffix(path, ".ps1") {
				return nil
			}
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			for _, m := range re.FindAllSubmatch(b, -1) {
				calls++
				method := string(m[1])
				if !dispatched[method] {
					t.Errorf("%s: IPC literal %q is not dispatched", path, method)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if calls < 50 {
		t.Fatal("caller inventory unexpectedly empty", calls)
	}
	t.Logf("checked %d caller literals and %d dispatched methods", calls, len(dispatched))
}
func ipcCaseStrings(sw *ast.SwitchStmt) map[string]bool {
	out := map[string]bool{}
	for _, stmt := range sw.Body.List {
		if clause, ok := stmt.(*ast.CaseClause); ok {
			for _, expr := range clause.List {
				if lit, ok := expr.(*ast.BasicLit); ok && lit.Kind == token.STRING {
					v, e := strconv.Unquote(lit.Value)
					if e == nil {
						out[v] = true
					}
				}
			}
		}
	}
	return out
}
func TestRelayPrimaryStatusIsReadOnlyAndDispatched(t *testing.T) {
	c := New(context.Background())
	defer c.Close()
	if _, err := c.Handle(context.Background(), "relay.primary.status", nil); err != nil {
		t.Fatal(err)
	}
	if len(c.relayPools) != 0 {
		t.Fatal("read-only status created a pool")
	}
}
