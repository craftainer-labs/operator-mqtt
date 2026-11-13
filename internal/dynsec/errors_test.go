package dynsec

import (
	"errors"
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		msg  string
		want error
	}{
		{"Client not found", ErrNotFound},
		{"Role not found", ErrNotFound},
		{"ACL not found", ErrNotFound},
		{"Role does not exist", ErrNotFound},
		{"Client already exists", ErrExists},
		{"Role already exists", ErrExists},
		{"ACL with this topic already exists", ErrExists},
		{"Invalid/missing username", ErrInvalid},
		{"Invalid ACL topic", ErrInvalid},
		{"Username not valid UTF-8", ErrInvalid},
		{"Empty password is not allowed", ErrInvalid},
		{"Unknown acltype", ErrInvalid},
		{"Unknown command", ErrInvalid},
		{"Internal error", ErrBroker},
		{"something else", ErrBroker},
	}
	for _, tt := range tests {
		err := classify("cmd", tt.msg)
		if !errors.Is(err, tt.want) {
			t.Errorf("classify(%q) = %v, want %v", tt.msg, err, tt.want)
		}
		if !strings.Contains(err.Error(), tt.msg) {
			t.Errorf("classify(%q) lost the broker's text: %v", tt.msg, err)
		}
	}
}
