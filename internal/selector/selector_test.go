package selector

import (
	"strings"
	"testing"

	"github.com/redhatua/iptables-exporter/internal/model"
	"github.com/redhatua/iptables-exporter/internal/parser"
)

func parse(t *testing.T, in string) []model.Table {
	t.Helper()
	tables, err := parser.Parse(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	return tables
}

const head = "*filter\n:INPUT ACCEPT [0:0]\n:OTHER - [0:0]\n"

func TestConventionSelectsInsideLongerComment(t *testing.T) {
	s, err := New(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	res := s.Select(parse(t, head+`[5:50] -A INPUT -m comment --comment "managed by x iptx:id=web.in:80 ok" -j ACCEPT`+"\nCOMMIT\n"))
	if len(res.Rules) != 1 || res.Rules[0].ID != "web.in:80" || res.Rules[0].Packets != 5 ||
		res.Rules[0].Bytes != 50 || res.Rules[0].Table != "filter" || res.Rules[0].Chain != "INPUT" {
		t.Fatalf("res = %+v", res)
	}
}

func TestConventionDisabled(t *testing.T) {
	s, _ := New(false, nil)
	res := s.Select(parse(t, head+`[1:1] -A INPUT -m comment --comment "iptx:id=a" -j ACCEPT`+"\nCOMMIT\n"))
	if len(res.Rules) != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestRegexWithAndWithoutGroup(t *testing.T) {
	s, err := New(false, []string{`^svc/(\w+)$`, `^plain-\d+$`})
	if err != nil {
		t.Fatal(err)
	}
	in := head +
		`[1:1] -A INPUT -m comment --comment "svc/web" -j ACCEPT` + "\n" +
		`[2:2] -A INPUT -m comment --comment "plain-42" -j ACCEPT` + "\n" +
		`[3:3] -A INPUT -m comment --comment "nothing" -j ACCEPT` + "\nCOMMIT\n"
	res := s.Select(parse(t, in))
	if len(res.Rules) != 2 || res.Rules[0].ID != "web" || res.Rules[1].ID != "plain-42" {
		t.Fatalf("res = %+v", res)
	}
}

func TestDuplicatesAreDroppedAndCounted(t *testing.T) {
	s, _ := New(true, nil)
	in := head +
		`[1:1] -A INPUT -m comment --comment "iptx:id=dup" -j ACCEPT` + "\n" +
		`[2:2] -A INPUT -p tcp -m comment --comment "iptx:id=dup" -j DROP` + "\n" +
		`[3:3] -A INPUT -m comment --comment "iptx:id=ok" -j ACCEPT` + "\n" +
		`[4:4] -A OTHER -m comment --comment "iptx:id=dup" -j ACCEPT` + "\nCOMMIT\n"
	res := s.Select(parse(t, in))
	if res.Duplicates != 2 {
		t.Fatalf("Duplicates = %d, want 2", res.Duplicates)
	}
	ids := map[string]bool{}
	for _, r := range res.Rules {
		ids[r.Chain+"/"+r.ID] = true
	}
	// Same ID in a different chain is a different scope and is kept.
	if len(res.Rules) != 2 || !ids["INPUT/ok"] || !ids["OTHER/dup"] {
		t.Fatalf("res = %+v", res)
	}
}

func TestOverlongRegexIDIsSkipped(t *testing.T) {
	s, _ := New(false, []string{`^(.+)$`})
	long := strings.Repeat("a", 129)
	res := s.Select(parse(t, head+`[1:1] -A INPUT -m comment --comment "`+long+`" -j ACCEPT`+"\nCOMMIT\n"))
	if len(res.Rules) != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestInvalidRegex(t *testing.T) {
	if _, err := New(true, []string{"("}); err == nil {
		t.Fatal("expected compile error")
	}
}

func TestConventionIDOver64IsNotSelected(t *testing.T) {
	s, _ := New(true, nil)
	id := strings.Repeat("a", 65)
	res := s.Select(parse(t, head+`[1:1] -A INPUT -m comment --comment "iptx:id=`+id+`" -j ACCEPT`+"\nCOMMIT\n"))
	if len(res.Rules) != 0 {
		t.Fatalf("res = %+v", res)
	}
}

func TestConventionIDExactly64IsSelected(t *testing.T) {
	s, _ := New(true, nil)
	id := strings.Repeat("a", 64)
	res := s.Select(parse(t, head+`[1:1] -A INPUT -m comment --comment "iptx:id=`+id+`" -j ACCEPT`+"\nCOMMIT\n"))
	if len(res.Rules) != 1 || res.Rules[0].ID != id {
		t.Fatalf("res = %+v", res)
	}
}

func TestConventionSkipsCommentWithoutIDAndUsesNext(t *testing.T) {
	s, _ := New(true, nil)
	in := head + `[1:1] -A INPUT -m comment --comment "first" -m comment --comment "iptx:id=b" -j ACCEPT` + "\nCOMMIT\n"
	res := s.Select(parse(t, in))
	if len(res.Rules) != 1 || res.Rules[0].ID != "b" {
		t.Fatalf("res = %+v", res)
	}
}
