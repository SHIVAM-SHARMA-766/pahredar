package cwe

import (
	"strings"
	"testing"
)

func TestParse(t *testing.T) {
	ws, err := parse(strings.NewReader("CWE-ID,Name,Weakness Abstraction\n79,\"Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')\",Base\n89,SQL Injection,Base\n"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ws) != 2 || ws[0].ID != "CWE-79" || !strings.Contains(ws[0].Name, "Cross-site") {
		t.Fatalf("got %+v", ws)
	}
	if _, err := parse(strings.NewReader("ID,Title\n1,x\n")); err == nil {
		t.Fatal("bad header accepted")
	}
}
