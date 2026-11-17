//go:build integration && iotcore

package integration

import (
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/iot"

	"github.com/craftainer-labs/lib-operator-go/pkg/cloud"
	"github.com/craftainer-labs/lib-operator-go/pkg/egress"
	"github.com/craftainer-labs/lib-operator-go/pkg/server"

	mqttv1alpha1 "github.com/craftainer-labs/operator-mqtt/api/v1alpha1"
	"github.com/craftainer-labs/operator-mqtt/internal/controller"
	"github.com/craftainer-labs/operator-mqtt/internal/iotcore"
)

// These tests run the operator's AWS IoT Core code (internal/iotcore and the
// probe) against moto 5.2.5, through the same cloud.Egress.AWS the operator
// uses, with EGRESS_MODE=allow-private and an endpointOverride (test wiring
// only), behind the tag recorder of iotproxy_test.go. See README.md here for
// what moto cannot check: a real MQTT TLS connect with the certificate, IRSA,
// IoT policy evaluation, and moto's random DescribeEndpoint host name.

// region and the dummy keys moto accepts.
const (
	motoRegion = "us-east-1"
	motoKey    = "AKIAMOTOTESTKEY00000"
	motoSecret = "moto-test-secret"
)

// iotEnv is a broker object that points the operator's AWS code at moto.
type iotEnv struct {
	srv    *mqttv1alpha1.ClusterMqttBroker
	cc     server.CloudConnection
	proxy  *tagProxy
	client *iotcore.Client
	cfg    controller.Config
}

func newIoTEnv(t *testing.T) iotEnv {
	t.Helper()
	upstream := os.Getenv("MOTO_ENDPOINT")
	if upstream == "" {
		t.Fatal("MOTO_ENDPOINT is not set; see test/integration/README.md")
	}
	proxy := newTagProxy(t, upstream)
	srv := &mqttv1alpha1.ClusterMqttBroker{}
	srv.Spec.Provider = &mqttv1alpha1.ClusterProvider{Type: cloud.ProviderAWS, AWS: &cloud.AWSClusterBlock{
		AWSBlock: cloud.AWSBlock{Region: motoRegion}, EndpointOverride: proxy.URL,
	}}
	srv.Spec.Credentials = &cloud.Credentials{Source: cloud.SourceSecret, SecretRef: &cloud.SecretRef{Name: "aws", Namespace: "operator"}}
	cc := server.CloudConnection{Credentials: map[string][]byte{
		cloud.KeyAWSAccessKeyID: []byte(motoKey), cloud.KeyAWSSecretAccessKey: []byte(motoSecret),
	}}
	cfg := controller.Config{IoT: controller.AWSIoT(egress.ModeAllowPrivate)}
	api, err := cfg.IoT(bg, srv, cc)
	if err != nil {
		t.Fatal(err)
	}
	return iotEnv{srv: srv, cc: cc, proxy: proxy, client: iotcore.New(api), cfg: cfg}
}

// policyName is a policy name of the test's own.
func policyName(prefix string) string { return name(prefix) }

// userPolicy makes the policy document of a claim whose certificate cert is.
func userPolicy(t *testing.T, cert iotcore.Cert, clientID string) string {
	t.Helper()
	scope, err := iotcore.ScopeOf(cert.ARN)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := iotcore.Document(scope, clientID, []iotcore.Rule{{Topic: "tenant/a/#", Publish: true, Subscribe: true}})
	if err != nil {
		t.Fatal(err)
	}
	return doc
}

func cleanup(t *testing.T, e iotEnv, name string) {
	t.Helper()
	t.Cleanup(func() {
		st, err := e.client.Observe(bg, name)
		if err != nil || !st.Exists {
			return
		}
		for _, c := range st.Certs {
			_ = e.client.Retire(bg, name, c)
		}
		_ = e.client.DeletePolicy(bg, name)
	})
}

// The probe reads the data endpoint (DescribeEndpoint, iot:Data-ATS) and the
// region of the provider block. moto answers with a random host name in the
// shape of the real one; only that shape can be checked.
func TestIoTProbeDiscoversTheEndpoint(t *testing.T) {
	e := newIoTEnv(t)
	res, err := controller.Prober{Config: e.cfg}.ProbeCloud(bg, e.srv, e.cc)
	if err != nil {
		t.Fatal(err)
	}
	d := res.Discovered
	if !strings.HasSuffix(d["endpoint"], ".iot."+motoRegion+".amazonaws.com") || d["region"] != motoRegion || d["port"] != "8883" || len(d) != 3 {
		t.Errorf("discovered = %v", d)
	}
	if res.Version != "" {
		t.Errorf("version = %q", res.Version)
	}

	// The refusals keep the cloud's words out of the error.
	bad := e.cc
	bad.Credentials = map[string][]byte{}
	if _, err := (controller.Prober{Config: e.cfg}).ProbeCloud(bg, e.srv, bad); !errors.Is(err, cloud.ErrCredentialsUnavailable) {
		t.Errorf("no keys: %v", err)
	}
}

// A claim's create makes the policy with the ownership tag, a certificate that
// starts INACTIVE and attaches it, then activates it.
func TestIoTCreatePolicyCertificateAttachActivate(t *testing.T) {
	e := newIoTEnv(t)
	name := policyName("it-create")
	cleanup(t, e, name)
	cert, err := e.client.NewCert(bg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.client.Retire(bg, name, cert.ARN) })
	if cert.PEM == "" || cert.Key() == "" || cert.ID == "" || iotcore.CertID(cert.ARN) != cert.ID {
		t.Fatalf("certificate: %v", cert)
	}
	doc := userPolicy(t, cert, name)
	const claim = "ns/user/uid-1"
	if err := e.client.CreatePolicy(bg, name, claim, doc); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Activate(bg, name, cert); err != nil {
		t.Fatal(err)
	}
	st, err := e.client.Observe(bg, name)
	if err != nil {
		t.Fatal(err)
	}
	if !st.Exists || st.Claim != claim || !iotcore.SameDocument(st.Document, doc) || len(st.Certs) != 1 || st.Certs[0] != cert.ARN {
		t.Errorf("state = %+v", st)
	}
	pem, err := e.client.CertPEM(bg, cert.ID)
	if err != nil || pem != cert.PEM {
		t.Errorf("CertPEM: %v", err)
	}

	// The same policy name again is ErrExists and changes nothing.
	if err := e.client.CreatePolicy(bg, name, claim, doc); !errors.Is(err, iotcore.ErrExists) {
		t.Errorf("second create: %v", err)
	}
}

// RotateBegin adds a second certificate to the policy while the first works;
// RotateFinish retires the first (inactive, detached, deleted).
func TestIoTRotationOverlapAndRetire(t *testing.T) {
	e := newIoTEnv(t)
	name := policyName("it-rotate")
	cleanup(t, e, name)
	first, err := e.client.NewCert(bg)
	if err != nil {
		t.Fatal(err)
	}
	doc := userPolicy(t, first, name)
	if err := e.client.CreatePolicy(bg, name, "ns/user/uid-2", doc); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Activate(bg, name, first); err != nil {
		t.Fatal(err)
	}

	second, err := e.client.NewCert(bg) // RotateBegin
	if err != nil {
		t.Fatal(err)
	}
	if err := e.client.Activate(bg, name, second); err != nil {
		t.Fatal(err)
	}
	st, err := e.client.Observe(bg, name)
	if err != nil || len(st.Certs) != 2 {
		t.Fatalf("during the overlap: %+v, %v", st, err)
	}

	if err := e.client.Retire(bg, name, first.ARN); err != nil { // RotateFinish
		t.Fatal(err)
	}
	if err := e.client.Retire(bg, name, first.ARN); err != nil { // idempotent
		t.Errorf("retire twice: %v", err)
	}
	st, err = e.client.Observe(bg, name)
	if err != nil || len(st.Certs) != 1 || st.Certs[0] != second.ARN {
		t.Fatalf("after RotateFinish: %+v, %v", st, err)
	}
	if _, err := e.client.CertPEM(bg, first.ID); !errors.Is(err, iotcore.ErrNotFound) {
		t.Errorf("the retired certificate is still there: %v", err)
	}

	// A changed document becomes the default version.
	changed := strings.ReplaceAll(doc, "tenant/a/", "tenant/b/")
	if err := e.client.SetDocument(bg, name, changed); err != nil {
		t.Fatal(err)
	}
	if st, err = e.client.Observe(bg, name); err != nil || !iotcore.SameDocument(st.Document, changed) {
		t.Errorf("document: %+v, %v", st, err)
	}
}

// Delete's order: the policy cannot go while a certificate is attached, so the
// certificates are retired first and the policy last; what is gone is not an
// error.
func TestIoTDeleteOrdering(t *testing.T) {
	e := newIoTEnv(t)
	name := policyName("it-delete")
	cleanup(t, e, name)
	cert, err := e.client.NewCert(bg)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.client.CreatePolicy(bg, name, "ns/user/uid-3", userPolicy(t, cert, name)); err != nil {
		t.Fatal(err)
	}
	if err := e.client.Activate(bg, name, cert); err != nil {
		t.Fatal(err)
	}

	if err := e.client.DeletePolicy(bg, name); err == nil {
		t.Fatal("the policy was deleted while a certificate was attached")
	}
	if st, err := e.client.Observe(bg, name); err != nil || !st.Exists {
		t.Fatalf("the policy is gone after a refused delete: %+v, %v", st, err)
	}
	if err := e.client.Retire(bg, name, cert.ARN); err != nil {
		t.Fatal(err)
	}
	if err := e.client.DeletePolicy(bg, name); err != nil {
		t.Fatal(err)
	}
	if st, err := e.client.Observe(bg, name); err != nil || st.Exists {
		t.Errorf("after the delete: %+v, %v", st, err)
	}
	if err := e.client.DeletePolicy(bg, name); err != nil {
		t.Errorf("delete twice: %v", err)
	}
	// The name is free again, with no tag left from the old policy.
	if err := e.client.CreatePolicy(bg, name, "ns/other/uid-4", userPolicy(t, cert, name)); err != nil {
		t.Fatal(err)
	}
	if st, err := e.client.Observe(bg, name); err != nil || st.Claim != "ns/other/uid-4" {
		t.Errorf("recreated: %+v, %v", st, err)
	}
}

// A policy of the derived name that another claim made, or nobody tagged, is
// seen as foreign: Observe shows its tag, CreatePolicy answers ErrExists and
// the policy stays as it was. (What the controller does with that answer, never
// adopting, is covered by its unit tests; this checks the cloud's side.)
func TestIoTForeignPolicyIsNotAdopted(t *testing.T) {
	e := newIoTEnv(t)
	cert, err := e.client.NewCert(bg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = e.client.Retire(bg, "", cert.ARN) })
	for _, tc := range []struct{ name, claim string }{
		{policyName("it-foreign"), "ns/someone-else/uid-9"},
		{policyName("it-untagged"), ""},
	} {
		cleanup(t, e, tc.name)
		doc := userPolicy(t, cert, tc.name)
		if tc.claim == "" {
			// Made outside the operator, with no tags at all.
			api, err := e.cfg.IoT(bg, e.srv, e.cc)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.CreatePolicy(bg, &iot.CreatePolicyInput{PolicyName: aws.String(tc.name), PolicyDocument: aws.String(doc)}); err != nil {
				t.Fatal(err)
			}
		} else if err := e.client.CreatePolicy(bg, tc.name, tc.claim, doc); err != nil {
			t.Fatal(err)
		}
		st, err := e.client.Observe(bg, tc.name)
		if err != nil || !st.Exists || st.Claim != tc.claim {
			t.Fatalf("%s: %+v, %v", tc.name, st, err)
		}
		const ours = "ns/user/uid-mine"
		if st.Claim == ours {
			t.Fatal("the foreign policy carries our claim")
		}
		if err := e.client.CreatePolicy(bg, tc.name, ours, doc); !errors.Is(err, iotcore.ErrExists) {
			t.Errorf("%s: create over it: %v", tc.name, err)
		}
		if after, err := e.client.Observe(bg, tc.name); err != nil || after.Claim != tc.claim || len(after.Certs) != 0 {
			t.Errorf("%s: changed: %+v, %v", tc.name, after, err)
		}
	}
}
