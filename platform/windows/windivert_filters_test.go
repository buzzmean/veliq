package windowsplatform

import (
	"go/ast"
	"go/parser"
	"go/token"
	"strconv"
	"strings"
	"testing"
)

func TestServiceWinDivertFilterInventory(t *testing.T) {
	inventory := map[string]uintptr{}
	for _, spec := range serviceWinDivertFilters(50165, false) {
		if _, duplicate := inventory[spec.name]; duplicate {
			t.Fatal("duplicate filter", spec.name)
		}
		inventory[spec.name] = spec.layer
	}
	seen := map[string]bool{}
	// Walk production Windows sources on Linux too. A new, literal or dynamic
	// filter cannot silently escape the mandatory DLL compilation inventory.
	pkgs, err := parser.ParseDir(token.NewFileSet(), ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	for filename, file := range pkgs["windowsplatform"].Files {
		if strings.HasSuffix(filename, "_test.go") {
			continue
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "openHandle" && sel.Sel.Name != "openHandlePriority") {
				return true
			}
			// The openHandle -> openHandlePriority delegate is checked at runtime.
			if filename == "capture_windows.go" && len(call.Args) == 4 {
				if ident, ok := call.Args[1].(*ast.Ident); ok && ident.Name == "layer" {
					return true
				}
			}
			ident, ok := call.Args[0].(*ast.Ident)
			if !ok {
				t.Errorf("%s: unregistered literal/dynamic filter", filename)
				return true
			}
			name := ident.Name
			if filename == "tcp_capture_windows.go" && name == "filter" {
				// Require the production TCP filter to come from the tested builder.
				value, ok := ident.Obj.Decl.(*ast.AssignStmt)
				if !ok || len(value.Rhs) != 1 {
					t.Fatal("TCP filter assignment changed")
				}
				builder, ok := value.Rhs[0].(*ast.CallExpr)
				if !ok {
					t.Fatal("TCP filter no longer uses builder")
				}
				fun, ok := builder.Fun.(*ast.Ident)
				if !ok || fun.Name != "nativeTCPNetworkFilter" {
					t.Fatal("TCP filter builder changed")
				}
				name = fun.Name
			}
			layer, ok := call.Args[1].(*ast.BasicLit)
			if !ok {
				t.Errorf("%s: dynamic layer missing from inventory", filename)
				return true
			}
			n, err := strconv.ParseUint(layer.Value, 0, 32)
			want, exists := inventory[name]
			if err != nil || !exists || uintptr(n) != want {
				t.Errorf("%s: unregistered filter/layer %s/%s", filename, name, layer.Value)
			}
			seen[name] = true
			return true
		})
	}
	for name := range inventory {
		if !seen[name] {
			t.Error("unused inventory entry", name)
		}
	}
}
