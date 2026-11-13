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
	// Foreign is set when the description is not empty and is not a marker: an
	// object someone else made. It never matches a claim, whatever its text.
	Foreign bool
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
// Marker with only Foreign set, so the object is refused rather than adopted,
// even if its text equals a claim; an empty description yields the zero Marker.
func ParseMarker(s string) Marker {
	var m Marker
	for i, f := range strings.Fields(s) {
		switch {
		case i == 0:
			if !strings.HasPrefix(f, markerPrefix) {
				return Marker{Foreign: true}
			}
			m.Claim = strings.TrimPrefix(f, markerPrefix)
		case strings.HasPrefix(f, "active="):
			m.Active = strings.TrimPrefix(f, "active=")
		}
	}
	return m
}
