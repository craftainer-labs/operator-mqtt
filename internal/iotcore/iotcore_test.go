package iotcore

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/iot/types"
)

var (
	bg      = context.Background()
	errBoom = errors.New("boom")
)

func TestClassify(t *testing.T) {
	if classify(nil) != nil {
		t.Error("nil is classified")
	}
	for code, want := range map[string]error{
		"ResourceNotFoundException":      ErrNotFound,
		"ResourceAlreadyExistsException": ErrExists,
		"AccessDeniedException":          ErrDenied,
		"UnauthorizedException":          ErrDenied,
		"UnrecognizedClientException":    ErrDenied,
		"InvalidSignatureException":      ErrDenied,
		"ExpiredTokenException":          ErrDenied,
		"InvalidRequestException":        ErrAPI,
	} {
		got := classify(fmt.Errorf("op: %w", apiErr(code)))
		if !errors.Is(got, want) {
			t.Errorf("%s: %v, want %v", code, got, want)
		}
	}
	if got := classify(errBoom); !errors.Is(got, ErrUnavailable) || !errors.Is(got, errBoom) {
		t.Errorf("transport error: %v", got)
	}
}

func TestEndpoint(t *testing.T) {
	f := newFakeIoT()
	c := New(f)
	got, err := c.Endpoint(bg)
	if err != nil || got != "abc123-ats.iot.eu-west-1.amazonaws.com" || !strings.Contains(f.joined(), "DescribeEndpoint iot:Data-ATS") {
		t.Errorf("endpoint = %q, %v; calls: %s", got, err, f.joined())
	}
	f.fail["DescribeEndpoint"] = apiErr("AccessDeniedException")
	if _, err := c.Endpoint(bg); !errors.Is(err, ErrDenied) {
		t.Errorf("denied: %v", err)
	}
	if _, err := New(emptyEndpoint{f}).Endpoint(bg); !errors.Is(err, ErrAPI) {
		t.Errorf("empty endpoint: %v", err)
	}
}

// emptyEndpoint answers DescribeEndpoint without an address.
type emptyEndpoint struct{ *fakeIoT }

func (emptyEndpoint) DescribeEndpoint(context.Context, *iot.DescribeEndpointInput, ...func(*iot.Options)) (*iot.DescribeEndpointOutput, error) {
	return &iot.DescribeEndpointOutput{}, nil
}

func TestNewCertAndActivate(t *testing.T) {
	f := newFakeIoT()
	c := New(f)
	if _, err := c.NewCert(bg); err != nil {
		t.Fatal(err)
	}
	cert, err := c.NewCert(bg)
	if err != nil || cert.ID != "cert0002" || cert.PEM != "PEM-cert0002" || cert.Key() != "KEY-cert0002" ||
		cert.ARN != "arn:aws:iot:eu-west-1:123456789012:cert/cert0002" || f.certs["cert0002"].status != "INACTIVE" {
		t.Fatalf("cert = %+v, %v", cert, err)
	}
	// The private key is never printed.
	for _, s := range []string{cert.String(), cert.GoString(), fmt.Sprintf("%v %+v %#v", cert, cert, cert)} {
		if strings.Contains(s, "KEY-") {
			t.Errorf("the key is printed: %s", s)
		}
	}

	if err := c.CreatePolicy(bg, "p", "ns/n/uid", `{}`); err != nil {
		t.Fatal(err)
	}
	f.reset()
	if err := c.Activate(bg, "p", cert); err != nil {
		t.Fatal(err)
	}
	// Attached before it is active.
	if got := f.joined(); got != "AttachPolicy p "+cert.ARN+"\nUpdateCertificate cert0002 ACTIVE" {
		t.Errorf("calls:\n%s", got)
	}
	for _, method := range []string{"AttachPolicy", "UpdateCertificate"} {
		f.fail[method] = errBoom
		if err := c.Activate(bg, "p", cert); !errors.Is(err, errBoom) {
			t.Errorf("%s: %v", method, err)
		}
		delete(f.fail, method)
	}

	f.fail["CreateKeysAndCertificate"] = errBoom
	if _, err := c.NewCert(bg); !errors.Is(err, errBoom) {
		t.Errorf("create: %v", err)
	}
}

func TestNewCertRefusesAnIncompleteAnswer(t *testing.T) {
	s := func(v string) *string { return &v }
	full := iot.CreateKeysAndCertificateOutput{
		CertificateArn: s("a"), CertificateId: s("i"), CertificatePem: s("p"), KeyPair: &types.KeyPair{PrivateKey: s("k")},
	}
	for name, mutate := range map[string]func(*iot.CreateKeysAndCertificateOutput){
		"no key pair": func(o *iot.CreateKeysAndCertificateOutput) { o.KeyPair = nil },
		"no key":      func(o *iot.CreateKeysAndCertificateOutput) { o.KeyPair = &types.KeyPair{} },
		"no arn":      func(o *iot.CreateKeysAndCertificateOutput) { o.CertificateArn = nil },
		"no id":       func(o *iot.CreateKeysAndCertificateOutput) { o.CertificateId = nil },
		"no pem":      func(o *iot.CreateKeysAndCertificateOutput) { o.CertificatePem = nil },
	} {
		out := full
		mutate(&out)
		if _, err := New(canned{fakeIoT: newFakeIoT(), out: &out}).NewCert(bg); !errors.Is(err, ErrAPI) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// canned answers CreateKeysAndCertificate with a fixed output.
type canned struct {
	*fakeIoT
	out *iot.CreateKeysAndCertificateOutput
}

func (c canned) CreateKeysAndCertificate(context.Context, *iot.CreateKeysAndCertificateInput, ...func(*iot.Options)) (*iot.CreateKeysAndCertificateOutput, error) {
	return c.out, nil
}

func TestCertPEM(t *testing.T) {
	f := newFakeIoT()
	c := New(f)
	cert, _ := c.NewCert(bg)
	if got, err := c.CertPEM(bg, cert.ID); err != nil || got != cert.PEM {
		t.Errorf("pem = %q, %v", got, err)
	}
	if _, err := c.CertPEM(bg, "absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("absent: %v", err)
	}
	if _, err := New(noDescription{f}).CertPEM(bg, "x"); !errors.Is(err, ErrAPI) {
		t.Errorf("no description: %v", err)
	}
}

// noDescription answers DescribeCertificate with nothing.
type noDescription struct{ *fakeIoT }

func (noDescription) DescribeCertificate(context.Context, *iot.DescribeCertificateInput, ...func(*iot.Options)) (*iot.DescribeCertificateOutput, error) {
	return &iot.DescribeCertificateOutput{}, nil
}

func TestCertID(t *testing.T) {
	for in, want := range map[string]string{
		"arn:aws:iot:eu-west-1:123456789012:cert/abc":   "abc",
		"arn:aws:iot:eu-west-1:123456789012:policy/abc": "",
		"arn:aws:s3:::bucket/cert/abc":                  "",
		"us-east-1:0000":                                "",
		"create-issued":                                 "",
		"":                                              "",
	} {
		if got := CertID(in); got != want {
			t.Errorf("CertID(%q) = %q, want %q", in, got, want)
		}
	}
}

// issued makes a policy with a certificate attached and active.
func issued(t *testing.T, f *fakeIoT, c *Client, policy string) Cert {
	t.Helper()
	if _, ok := f.policies[policy]; !ok {
		if err := c.CreatePolicy(bg, policy, "ns/n/uid", `{"a":1}`); err != nil {
			t.Fatal(err)
		}
	}
	cert, err := c.NewCert(bg)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Activate(bg, policy, cert); err != nil {
		t.Fatal(err)
	}
	return cert
}

func TestRetire(t *testing.T) {
	f := newFakeIoT()
	c := New(f)
	cert := issued(t, f, c, "p")
	f.reset()
	if err := c.Retire(bg, "p", cert.ARN); err != nil {
		t.Fatal(err)
	}
	// Inactive first, then detached, then deleted.
	if got := f.joined(); got != "UpdateCertificate cert0001 INACTIVE\nDetachPolicy p "+cert.ARN+"\nDeleteCertificate cert0001" {
		t.Errorf("calls:\n%s", got)
	}
	if len(f.certs) != 0 || len(f.attached["p"]) != 0 {
		t.Errorf("left: %v %v", f.certs, f.attached)
	}
	// A certificate that is gone is not an error, and the policy may be left out.
	if err := c.Retire(bg, "p", cert.ARN); err != nil {
		t.Errorf("gone: %v", err)
	}
	lone, _ := c.NewCert(bg)
	f.reset()
	if err := c.Retire(bg, "", lone.ARN); err != nil || strings.Contains(f.joined(), "DetachPolicy") {
		t.Errorf("no policy: %v\n%s", err, f.joined())
	}
	// Detached already, or deleted meanwhile.
	again := issued(t, f, c, "p")
	f.attached["p"] = nil
	if err := c.Retire(bg, "p", again.ARN); err != nil {
		t.Errorf("detached: %v", err)
	}
	if err := c.Retire(bg, "p", "not-an-arn"); !errors.Is(err, ErrBadARN) {
		t.Errorf("bad arn: %v", err)
	}
	for _, method := range []string{"UpdateCertificate", "DetachPolicy", "DeleteCertificate"} {
		cert := issued(t, f, c, "p")
		f.fail[method] = errBoom
		if err := c.Retire(bg, "p", cert.ARN); !errors.Is(err, errBoom) {
			t.Errorf("%s: %v", method, err)
		}
		delete(f.fail, method)
	}
	// Deleted between the detach and the delete.
	gone := issued(t, f, c, "p")
	f.fail["DeleteCertificate"] = apiErr("ResourceNotFoundException")
	if err := c.Retire(bg, "p", gone.ARN); err != nil {
		t.Errorf("deleted meanwhile: %v", err)
	}
}

func TestObserve(t *testing.T) {
	f := newFakeIoT()
	c := New(f)
	st, err := c.Observe(bg, "p")
	if err != nil || st.Exists {
		t.Fatalf("absent: %+v, %v", st, err)
	}
	cert := issued(t, f, c, "p")
	second := issued(t, f, c, "p")
	for _, size := range []int{0, 1} {
		f.pageSize = size
		st, err = c.Observe(bg, "p")
		want := State{
			Exists: true, PolicyARN: "arn:aws:iot:eu-west-1:123456789012:policy/p", Document: `{"a":1}`,
			Claim: "ns/n/uid", Certs: []string{cert.ARN, second.ARN},
		}
		if err != nil || fmt.Sprint(st) != fmt.Sprint(want) {
			t.Errorf("page size %d: %+v, %v", size, st, err)
		}
	}
	for _, method := range []string{"GetPolicy", "ListTagsForResource", "ListTargetsForPolicy"} {
		f.fail[method] = errBoom
		if _, err := c.Observe(bg, "p"); !errors.Is(err, errBoom) {
			t.Errorf("%s: %v", method, err)
		}
		delete(f.fail, method)
	}
}

func TestPolicyLifecycle(t *testing.T) {
	f := newFakeIoT()
	c := New(f)
	if err := c.CreatePolicy(bg, "p", "claim", `{"v":1}`); err != nil {
		t.Fatal(err)
	}
	if f.policies["p"].tags[ClaimTag] != "claim" {
		t.Errorf("tags = %v", f.policies["p"].tags)
	}
	if err := c.CreatePolicy(bg, "p", "other", `{}`); !errors.Is(err, ErrExists) {
		t.Errorf("duplicate: %v", err)
	}

	// Seven edits never reach the limit of five versions.
	for i := 2; i < 9; i++ {
		if err := c.SetDocument(bg, "p", fmt.Sprintf(`{"v":%d}`, i)); err != nil {
			t.Fatalf("edit %d: %v", i, err)
		}
	}
	if st, _ := c.Observe(bg, "p"); st.Document != `{"v":8}` || len(f.policies["p"].versions) != 2 {
		t.Errorf("document = %q, %d versions", st.Document, len(f.policies["p"].versions))
	}
	for _, method := range []string{"ListPolicyVersions", "DeletePolicyVersion", "CreatePolicyVersion"} {
		f.fail[method] = errBoom
		if err := c.SetDocument(bg, "p", `{"v":9}`); !errors.Is(err, errBoom) {
			t.Errorf("%s: %v", method, err)
		}
		delete(f.fail, method)
	}
	// A version deleted meanwhile is not an error.
	if err := c.SetDocument(bg, "p", `{"v":9}`); err != nil {
		t.Fatal(err)
	}
	f.fail["DeletePolicyVersion"] = apiErr("ResourceNotFoundException")
	if err := c.SetDocument(bg, "p", `{"v":9}`); err != nil {
		t.Errorf("version gone: %v", err)
	}
	delete(f.fail, "DeletePolicyVersion")

	for _, method := range []string{"DeletePolicyVersion", "ListPolicyVersions", "DeletePolicy"} {
		f.fail[method] = errBoom
		if err := c.DeletePolicy(bg, "p"); !errors.Is(err, errBoom) {
			t.Errorf("delete, %s: %v", method, err)
		}
		delete(f.fail, method)
	}
	if err := c.DeletePolicy(bg, "p"); err != nil || len(f.policies) != 0 {
		t.Errorf("delete: %v, %v", err, f.policies)
	}
	// Gone is gone, whether the versions or the policy say so.
	if err := c.DeletePolicy(bg, "p"); err != nil {
		t.Errorf("delete again: %v", err)
	}
	if err := c.CreatePolicy(bg, "q", "claim", `{}`); err != nil {
		t.Fatal(err)
	}
	f.fail["DeletePolicy"] = apiErr("ResourceNotFoundException")
	if err := c.DeletePolicy(bg, "q"); err != nil {
		t.Errorf("policy gone: %v", err)
	}
}

func TestSameDocument(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{`{"a":[1,2]}`, "{ \"a\" : [1, 2] }", true},
		{`{"a":[1,2]}`, `{"a":[2,1]}`, false},
		{`{`, `{}`, false},
		{`{}`, `{`, false},
	} {
		if got := SameDocument(tc.a, tc.b); got != tc.want {
			t.Errorf("SameDocument(%q, %q) = %t", tc.a, tc.b, got)
		}
	}
}

func TestScopeOf(t *testing.T) {
	got, err := ScopeOf("arn:aws:iot:eu-west-1:123456789012:cert/abc")
	if err != nil || got != (Scope{Partition: "aws", Region: "eu-west-1", Account: "123456789012"}) {
		t.Errorf("scope = %+v, %v", got, err)
	}
	for _, bad := range []string{"", "x", "arn:aws:s3:::b", "arn:aws:iot::123456789012:cert/a", "arn:aws:iot:eu-west-1::cert/a"} {
		if _, err := ScopeOf(bad); !errors.Is(err, ErrBadARN) {
			t.Errorf("%q: %v", bad, err)
		}
	}
}
