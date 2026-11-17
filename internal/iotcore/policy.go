package iotcore

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Rule is one ACL of a user: a topic filter (already under the tenant root)
// and what the user may do with it.
type Rule struct {
	Topic     string
	Publish   bool
	Subscribe bool
}

// statement is one statement of an IoT policy document.
type statement struct {
	Effect   string   `json:"Effect"`
	Action   []string `json:"Action"`
	Resource []string `json:"Resource"`
}

// document is an IoT policy document.
type document struct {
	Version   string      `json:"Version"`
	Statement []statement `json:"Statement"`
}

// Document is the policy of a user: iot:Connect with the client id and no
// other, and the rules' topics. A rule that publishes allows iot:Publish on the
// topics it matches; one that subscribes allows iot:Subscribe on the filter
// itself and iot:Receive on the topics it matches. The document has no
// whitespace, which counts against the 2048 characters IoT allows.
//
// A topic with a wildcard of IoT's own (* or ?) is refused, because it would
// widen the grant; so is %u, which has no meaning for a certificate. %c is the
// client id (the policy variable ${iot:ClientId}). MQTT's + and # become * in
// the resources of topics, so a filter such as a/+/b also lets the user publish
// to a/x/y/b: the tenant root still bounds it.
func Document(s Scope, clientID string, rules []Rule) (string, error) {
	arnOf := func(kind, name string) string {
		return fmt.Sprintf("arn:%s:iot:%s:%s:%s/%s", s.Partition, s.Region, s.Account, kind, name)
	}
	var topics, filters, publish = map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, r := range rules {
		if strings.ContainsAny(r.Topic, "*?") || strings.Contains(r.Topic, "%u") {
			return "", ErrInvalidTopic
		}
		t := strings.ReplaceAll(r.Topic, "%c", "${iot:ClientId}")
		if r.Publish {
			for _, x := range topicNames(t) {
				publish[arnOf("topic", x)] = true
			}
		}
		if r.Subscribe {
			filters[arnOf("topicfilter", t)] = true
			for _, x := range topicNames(t) {
				topics[arnOf("topic", x)] = true
			}
		}
	}
	doc := document{Version: "2012-10-17", Statement: []statement{{
		Effect: "Allow", Action: []string{"iot:Connect"}, Resource: []string{arnOf("client", clientID)},
	}}}
	for _, g := range []struct {
		action string
		set    map[string]bool
	}{{"iot:Publish", publish}, {"iot:Subscribe", filters}, {"iot:Receive", topics}} {
		if len(g.set) > 0 {
			doc.Statement = append(doc.Statement, statement{
				Effect: "Allow", Action: []string{g.action}, Resource: slices.Sorted(maps.Keys(g.set)),
			})
		}
	}
	b, err := json.Marshal(doc)
	return string(b), err
}

// topicNames turns a topic filter into the resource names of the topics it
// matches: each + level and a last # level become *, and a filter that ends in
// /# also names the parent topic, which # matches too.
func topicNames(filter string) []string {
	levels := strings.Split(filter, "/")
	for i, l := range levels {
		if l == "+" || l == "#" {
			levels[i] = "*"
		}
	}
	names := []string{strings.Join(levels, "/")}
	if strings.HasSuffix(filter, "/#") {
		names = append(names, strings.Join(levels[:len(levels)-1], "/"))
	}
	return names
}
