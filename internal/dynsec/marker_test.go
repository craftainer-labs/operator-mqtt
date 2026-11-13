package dynsec

import "testing"

func TestMarker(t *testing.T) {
	tests := []struct {
		m    Marker
		text string
	}{
		{Marker{Claim: "ns/name/uid"}, "craftainer.dev/claim=ns/name/uid"},
		{Marker{Claim: "ns/name/uid", Active: "b"}, "craftainer.dev/claim=ns/name/uid active=b"},
	}
	for _, tt := range tests {
		if got := tt.m.String(); got != tt.text {
			t.Errorf("String() = %q, want %q", got, tt.text)
		}
		if got := ParseMarker(tt.text); got != tt.m {
			t.Errorf("ParseMarker(%q) = %+v, want %+v", tt.text, got, tt.m)
		}
	}
}

func TestParseMarkerForeignText(t *testing.T) {
	if got := ParseMarker(""); got != (Marker{}) {
		t.Errorf("empty: %+v", got)
	}
	// Not a marker: the claim is the text itself, which matches no claim
	// <namespace>/<name>/<uid>. Unknown fields after the claim are ignored.
	if got := ParseMarker("made by hand"); got.Claim != "made" || got.Active != "" {
		t.Errorf("foreign: %+v", got)
	}
	if got := ParseMarker("craftainer.dev/claim=a/b/c future=1 active=a"); got != (Marker{Claim: "a/b/c", Active: "a"}) {
		t.Errorf("unknown field: %+v", got)
	}
}
