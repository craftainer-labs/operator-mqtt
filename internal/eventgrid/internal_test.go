package eventgrid

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

var errStep = errors.New("a step failed")

// Each step of NewCert that can fail is an ErrAPI that names no key material.
func TestNewCertFailures(t *testing.T) {
	genKey, serial, sign, enc := generateKey, newSerial, signCert, encodeKey
	t.Cleanup(func() { generateKey, newSerial, signCert, encodeKey = genKey, serial, sign, enc })
	for name, fail := range map[string]func(){
		"key":    func() { generateKey = func() (*ecdsa.PrivateKey, error) { return nil, errStep } },
		"serial": func() { newSerial = func() (*big.Int, error) { return nil, errStep } },
		"sign": func() {
			signCert = func(io.Reader, *x509.Certificate, *x509.Certificate, any, any) ([]byte, error) { return nil, errStep }
		},
		"encode": func() { encodeKey = func(any) ([]byte, error) { return nil, errStep } },
	} {
		generateKey, newSerial, signCert, encodeKey = genKey, serial, sign, enc
		fail()
		if c, err := NewCert("client", time.Now()); !errors.Is(err, ErrAPI) || c.Key() != "" || c.PEM != "" {
			t.Errorf("%s: %+v, %v", name, c, err)
		}
	}
}

func TestClassifyAuthenticationFailures(t *testing.T) {
	if err := classify(&azidentity.AuthenticationFailedError{}); !errors.Is(err, ErrDenied) {
		t.Errorf("authentication failed: %v", err)
	}
	if err := classify(errStep); !errors.Is(err, ErrUnavailable) {
		t.Errorf("transport: %v", err)
	}
	if classify(nil) != nil {
		t.Error("nil")
	}
}

type noCredential struct{}

func (noCredential) GetToken(context.Context, policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return azcore.AccessToken{}, errStep
}

func TestNewRefusesAnIncompleteCloud(t *testing.T) {
	opts := &arm.ClientOptions{ClientOptions: azcore.ClientOptions{Cloud: cloud.Configuration{ActiveDirectoryAuthorityHost: "https://login.example"}}}
	if _, err := New("sub", "rg", "ns", noCredential{}, opts); !errors.Is(err, ErrAPI) {
		t.Errorf("New = %v", err)
	}
}
