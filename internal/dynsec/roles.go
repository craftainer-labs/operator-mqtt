package dynsec

import (
	"cmp"
	"context"
	"slices"
)

// ACLType is the kind of access a role ACL grants or denies, in the plugin's
// words. The subscribe and unsubscribe kinds match the topic filter a client
// sends, with + and # in the ACL topic standing for a level and for the rest
// (sub_acl_check in the plugin); the publish kinds match the topic of a message
// against the ACL topic.
type ACLType string

// The ACL types the operator writes. The plugin has more (subscribeLiteral,
// unsubscribeLiteral) that it only reads, for a role someone else made.
const (
	// ACLPublishSend lets a client publish to matching topics.
	ACLPublishSend ACLType = "publishClientSend"
	// ACLPublishReceive lets matching messages be delivered to a client.
	ACLPublishReceive ACLType = "publishClientReceive"
	// ACLSubscribePattern lets a client subscribe with matching filters.
	ACLSubscribePattern ACLType = "subscribePattern"
	// ACLUnsubscribePattern lets a client unsubscribe matching filters.
	ACLUnsubscribePattern ACLType = "unsubscribePattern"
)

// RoleACL is one rule of a role.
type RoleACL struct {
	Type     ACLType
	Topic    string
	Priority int
	Allow    bool
}

// RoleInfo is what GetRole returns.
type RoleInfo struct {
	Name            string
	TextDescription string
	ACLs            []RoleACL
}

// ACLsFor returns the rules that allow publishing to, subscribing to, or both,
// on a topic pattern: sending for a publisher; the filter, its unsubscribe and
// delivery for a subscriber.
func ACLsFor(topic string, publish, subscribe bool) []RoleACL {
	var acls []RoleACL
	if publish {
		acls = append(acls, RoleACL{Type: ACLPublishSend, Topic: topic, Allow: true})
	}
	if subscribe {
		acls = append(acls,
			RoleACL{Type: ACLSubscribePattern, Topic: topic, Allow: true},
			RoleACL{Type: ACLUnsubscribePattern, Topic: topic, Allow: true},
			RoleACL{Type: ACLPublishReceive, Topic: topic, Allow: true},
		)
	}
	return acls
}

type aclKey struct {
	typ   ACLType
	topic string
}

func indexACLs(acls []RoleACL) map[aclKey]RoleACL {
	m := make(map[aclKey]RoleACL, len(acls))
	for _, a := range acls {
		m[aclKey{a.Type, a.Topic}] = a
	}
	return m
}

func sortACLs(acls []RoleACL) {
	slices.SortFunc(acls, func(a, b RoleACL) int {
		return cmp.Or(cmp.Compare(a.Type, b.Type), cmp.Compare(a.Topic, b.Topic))
	})
}

func aclJSON(acls []RoleACL) []map[string]any {
	out := make([]map[string]any, len(acls))
	for i, a := range acls {
		out[i] = map[string]any{"acltype": string(a.Type), "topic": a.Topic, "priority": a.Priority, "allow": a.Allow}
	}
	return out
}

// CreateRole creates a role with its rules. The topics must be valid MQTT
// topic filters: createRole, unlike addRoleACL, does not check them and drops a
// rule it cannot use without an error. ErrExists when the name is taken.
func (a *Admin) CreateRole(ctx context.Context, name, description string, acls []RoleACL) error {
	_, err := a.do(ctx, "createRole", map[string]any{
		"rolename":        name,
		"textdescription": description,
		"acls":            aclJSON(acls),
	})
	return err
}

// GetRole reads a role with its rules. ErrNotFound when there is none.
func (a *Admin) GetRole(ctx context.Context, name string) (RoleInfo, error) {
	data, err := a.do(ctx, "getRole", map[string]any{"rolename": name})
	if err != nil {
		return RoleInfo{}, err
	}
	var d struct {
		Role struct {
			Rolename        string `json:"rolename"`
			TextDescription string `json:"textdescription"`
			ACLs            []struct {
				ACLType  string `json:"acltype"`
				Topic    string `json:"topic"`
				Priority int    `json:"priority"`
				Allow    bool   `json:"allow"`
			} `json:"acls"`
		} `json:"role"`
	}
	if err := decode("getRole", data, &d); err != nil {
		return RoleInfo{}, err
	}
	info := RoleInfo{Name: d.Role.Rolename, TextDescription: d.Role.TextDescription}
	for _, r := range d.Role.ACLs {
		info.ACLs = append(info.ACLs, RoleACL{Type: ACLType(r.ACLType), Topic: r.Topic, Priority: r.Priority, Allow: r.Allow})
	}
	return info, nil
}

// DeleteRole removes a role and disconnects the logins that hold it.
// ErrNotFound when there is none.
func (a *Admin) DeleteRole(ctx context.Context, name string) error {
	_, err := a.do(ctx, "deleteRole", map[string]any{"rolename": name})
	return err
}

// SetRoleDescription replaces a role's text description, which holds the
// Marker, and leaves its rules alone. ErrNotFound when there is none.
func (a *Admin) SetRoleDescription(ctx context.Context, name, description string) error {
	_, err := a.do(ctx, "modifyRole", map[string]any{"rolename": name, "textdescription": description})
	return err
}

// AddRoleACL adds a rule and disconnects the logins that hold the role, so the
// rule holds for sessions already open. ErrExists when the role has a rule of
// that type and topic; ErrInvalid for a topic that is not a valid filter.
func (a *Admin) AddRoleACL(ctx context.Context, role string, acl RoleACL) error {
	_, err := a.do(ctx, "addRoleACL", map[string]any{
		"rolename": role, "acltype": string(acl.Type), "topic": acl.Topic,
		"priority": acl.Priority, "allow": acl.Allow,
	})
	return err
}

// RemoveRoleACL removes the rule of a type and topic and disconnects the
// logins that hold the role. ErrNotFound for a missing role or rule.
func (a *Admin) RemoveRoleACL(ctx context.Context, role string, typ ACLType, topic string) error {
	_, err := a.do(ctx, "removeRoleACL", map[string]any{"rolename": role, "acltype": string(typ), "topic": topic})
	return err
}

// SyncRoleACLs makes the role's rules exactly want. It removes what is not
// wanted or differs, then adds what is missing, one rule at a time, because
// modifyRole replaces the rules without disconnecting the sessions that were
// admitted under the old ones, and a revoked rule has to take effect. A role
// that already has them is left untouched and nobody is disconnected.
func (a *Admin) SyncRoleACLs(ctx context.Context, role string, want []RoleACL) error {
	info, err := a.GetRole(ctx, role)
	if err != nil {
		return err
	}
	have, wanted := indexACLs(info.ACLs), indexACLs(want)
	var del, add []RoleACL
	for k, h := range have {
		if w, ok := wanted[k]; !ok || w != h {
			del = append(del, h)
		}
	}
	for k, w := range wanted {
		if h, ok := have[k]; !ok || w != h {
			add = append(add, w)
		}
	}
	sortACLs(del)
	sortACLs(add)
	for _, d := range del {
		if err := a.RemoveRoleACL(ctx, role, d.Type, d.Topic); err != nil {
			return err
		}
	}
	for _, w := range add {
		if err := a.AddRoleACL(ctx, role, w); err != nil {
			return err
		}
	}
	return nil
}
