package iotcore

import (
	"encoding/json"
	"errors"
	"slices"
	"testing"
)

var testScope = Scope{Partition: "aws", Region: "eu-west-1", Account: "123456789012"}

const arnPrefix = "arn:aws:iot:eu-west-1:123456789012:"

// statements parses a document into action -> resources.
func statements(t *testing.T, doc string) map[string][]string {
	t.Helper()
	var d document
	if err := json.Unmarshal([]byte(doc), &d); err != nil || d.Version != "2012-10-17" {
		t.Fatalf("document %q: %v", doc, err)
	}
	out := map[string][]string{}
	for _, s := range d.Statement {
		if s.Effect != "Allow" || len(s.Action) != 1 {
			t.Fatalf("statement = %+v", s)
		}
		out[s.Action[0]] = s.Resource
	}
	return out
}

func TestDocument(t *testing.T) {
	doc, err := Document(testScope, "ns-app-abc", []Rule{
		{Topic: "ns/sensors/+/telemetry", Publish: true},
		{Topic: "ns/commands/#", Subscribe: true},
		{Topic: "ns/both/%c", Publish: true, Subscribe: true},
		{Topic: "ns/commands/#", Subscribe: true},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := statements(t, doc)
	want := map[string][]string{
		"iot:Connect": {arnPrefix + "client/ns-app-abc"},
		"iot:Publish": {arnPrefix + "topic/ns/both/${iot:ClientId}", arnPrefix + "topic/ns/sensors/*/telemetry"},
		"iot:Subscribe": {
			arnPrefix + "topicfilter/ns/both/${iot:ClientId}", arnPrefix + "topicfilter/ns/commands/#",
		},
		"iot:Receive": {
			arnPrefix + "topic/ns/both/${iot:ClientId}", arnPrefix + "topic/ns/commands", arnPrefix + "topic/ns/commands/*",
		},
	}
	if len(got) != len(want) {
		t.Fatalf("statements = %v", got)
	}
	for action, res := range want {
		if !slices.Equal(got[action], res) {
			t.Errorf("%s = %v, want %v", action, got[action], res)
		}
	}
}

// With no rule the user may connect and do nothing else; the same document
// comes out whatever the order of the rules.
func TestDocumentIsStable(t *testing.T) {
	doc, err := Document(testScope, "c", nil)
	if err != nil || len(statements(t, doc)) != 1 {
		t.Errorf("no rules: %q, %v", doc, err)
	}
	a, _ := Document(testScope, "c", []Rule{{Topic: "a", Publish: true}, {Topic: "b", Publish: true}})
	b, _ := Document(testScope, "c", []Rule{{Topic: "b", Publish: true}, {Topic: "a", Publish: true}})
	if a != b {
		t.Errorf("order matters:\n%s\n%s", a, b)
	}
}

// A topic that could widen the grant is refused.
func TestDocumentRefusesWideningTopics(t *testing.T) {
	for _, topic := range []string{"ns/a*", "ns/a?b", "ns/%u/x"} {
		if _, err := Document(testScope, "c", []Rule{{Topic: topic, Publish: true}}); !errors.Is(err, ErrInvalidTopic) {
			t.Errorf("%q: %v", topic, err)
		}
	}
}

func TestTopicNames(t *testing.T) {
	for in, want := range map[string][]string{
		"a/b":     {"a/b"},
		"a/+/b":   {"a/*/b"},
		"a/#":     {"a/*", "a"},
		"#":       {"*"},
		"a/b+c/#": {"a/b+c/*", "a/b+c"},
	} {
		if got := topicNames(in); !slices.Equal(got, want) {
			t.Errorf("topicNames(%q) = %v, want %v", in, got, want)
		}
	}
}
