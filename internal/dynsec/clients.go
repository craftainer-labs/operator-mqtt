package dynsec

import "context"

// ClientSpec is what CreateClient makes. Dynsec calls a login a "client"; it is
// what an MqttUser's binding Secret carries.
type ClientSpec struct {
	Username string
	Password string
	// TextDescription holds the ownership Marker.
	TextDescription string
	// Roles are the role names to grant, with the plugin's default priority.
	Roles []string
}

// ClientInfo is what GetClient returns. The password is never part of it: the
// plugin does not return it.
type ClientInfo struct {
	Username        string
	TextDescription string
	Disabled        bool
	Roles           []string
}

func roleRefs(names []string) []map[string]any {
	refs := make([]map[string]any, len(names))
	for i, n := range names {
		refs[i] = map[string]any{"rolename": n}
	}
	return refs
}

// CreateClient creates a login. ErrExists when the username is taken.
func (a *Admin) CreateClient(ctx context.Context, spec ClientSpec) error {
	_, err := a.do(ctx, "createClient", map[string]any{
		"username":        spec.Username,
		"password":        spec.Password,
		"textdescription": spec.TextDescription,
		"roles":           roleRefs(spec.Roles),
	})
	return err
}

// GetClient reads a login. ErrNotFound when there is none.
func (a *Admin) GetClient(ctx context.Context, username string) (ClientInfo, error) {
	data, err := a.do(ctx, "getClient", map[string]any{"username": username})
	if err != nil {
		return ClientInfo{}, err
	}
	var d struct {
		Client struct {
			Username        string `json:"username"`
			TextDescription string `json:"textdescription"`
			Disabled        bool   `json:"disabled"`
			Roles           []struct {
				Rolename string `json:"rolename"`
			} `json:"roles"`
		} `json:"client"`
	}
	if err := decode("getClient", data, &d); err != nil {
		return ClientInfo{}, err
	}
	info := ClientInfo{
		Username:        d.Client.Username,
		TextDescription: d.Client.TextDescription,
		Disabled:        d.Client.Disabled,
	}
	for _, r := range d.Client.Roles {
		info.Roles = append(info.Roles, r.Rolename)
	}
	return info, nil
}

// DeleteClient removes a login and disconnects its sessions. ErrNotFound when
// there is none.
func (a *Admin) DeleteClient(ctx context.Context, username string) error {
	_, err := a.do(ctx, "deleteClient", map[string]any{"username": username})
	return err
}

// SetClientPassword replaces a login's password and disconnects its sessions.
// ErrNotFound when there is no such login; an empty password is ErrInvalid.
func (a *Admin) SetClientPassword(ctx context.Context, username, password string) error {
	_, err := a.do(ctx, "setClientPassword", map[string]any{"username": username, "password": password})
	return err
}

// EnableClient lets a login connect again. ErrNotFound when there is none.
func (a *Admin) EnableClient(ctx context.Context, username string) error {
	_, err := a.do(ctx, "enableClient", map[string]any{"username": username})
	return err
}

// DisableClient stops a login from connecting and disconnects its sessions.
// ErrNotFound when there is none.
func (a *Admin) DisableClient(ctx context.Context, username string) error {
	_, err := a.do(ctx, "disableClient", map[string]any{"username": username})
	return err
}

// AddClientRole grants a role. ErrNotFound for a missing login or role.
func (a *Admin) AddClientRole(ctx context.Context, username, role string) error {
	_, err := a.do(ctx, "addClientRole", map[string]any{"username": username, "rolename": role})
	return err
}

// RemoveClientRole takes a role away. ErrNotFound for a missing login or role.
func (a *Admin) RemoveClientRole(ctx context.Context, username, role string) error {
	_, err := a.do(ctx, "removeClientRole", map[string]any{"username": username, "rolename": role})
	return err
}
