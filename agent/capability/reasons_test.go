package capability

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var reasonCodePattern = regexp.MustCompile(`^AF-CAP-[A-Z0-9-]+$`)

// TestEveryReasonCodeIsDocumented parses the non-test sources of this package
// and asserts that every AF-CAP- string literal appears in ReasonCodes, that
// every documented code is well-formed, and that no code is documented twice.
func TestEveryReasonCodeIsDocumented(t *testing.T) {
	t.Parallel()
	documented := make(map[string]ReasonDescription)
	for _, description := range ReasonCodes() {
		if !reasonCodePattern.MatchString(description.Code) {
			t.Errorf("code %q is not a bounded AF-CAP- identifier", description.Code)
		}
		if strings.TrimSpace(description.Meaning) == "" {
			t.Errorf("code %q has no meaning", description.Code)
		}
		if _, duplicate := documented[description.Code]; duplicate {
			t.Errorf("code %q is documented twice", description.Code)
		}
		documented[description.Code] = description
	}
	if description := documented[ReasonOK]; description.FailsClosed {
		t.Error("AF-CAP-OK must not be marked fail-closed")
	}

	fileSet := token.NewFileSet()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}
	used := make(map[string]struct{})
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fileSet, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		ast.Inspect(file, func(node ast.Node) bool {
			literal, ok := node.(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING {
				return true
			}
			value, err := strconv.Unquote(literal.Value)
			if err != nil {
				return true
			}
			if strings.HasPrefix(value, "AF-CAP-") {
				used[value] = struct{}{}
			}
			return true
		})
	}
	if len(used) == 0 {
		t.Fatal("no AF-CAP- literals found; the scan is broken")
	}
	for code := range used {
		if _, ok := documented[code]; !ok {
			t.Errorf("code %q is emitted but not documented in ReasonCodes", code)
		}
	}
	for code := range documented {
		if _, ok := used[code]; !ok {
			t.Errorf("code %q is documented but never declared", code)
		}
	}
}
