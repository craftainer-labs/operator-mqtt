package dynsec

import "strings"

// markerPrefix starts the ownership marker kept in the text description of a
// client and of a role (ADR 0002 section 10): dynsec has no comments, and the
// description is the free text the plugin stores with each object.
const markerPrefix = "craftainer.dev/claim="

// Marker is the text description of an object the operator made: the owning
// claim as <namespace>/<name>/<uid>, and for a role which of the two logins
// (a or b) is the active one.
type Marker struct {
	Claim  string
	Active string
}

// String renders the description; an empty Active is left out.
func (m Marker) String() string {
	s := markerPrefix + m.Claim
	if m.Active != "" {
		s += " active=" + m.Active
	}
	return s
}

// ParseMarker reads a description. A description that is not a marker yields a
// Claim that matches no claim, so the object is refused rather than adopted; an
// empty description yields the zero Marker.
func ParseMarker(s string) Marker {
	var m Marker
	for i, f := range strings.Fields(s) {
		switch {
		case i == 0:
			m.Claim = strings.TrimPrefix(f, markerPrefix)
		case strings.HasPrefix(f, "active="):
			m.Active = strings.TrimPrefix(f, "active=")
		}
	}
	return m
}
