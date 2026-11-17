package controller

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/smithy-go"

	"github.com/craftainer-labs/operator-mqtt/internal/iotcore"
)

// fakeIoT is AWS IoT Core in memory behind API: the calls the package makes,
// with the answers the real service gives for a missing object, a name taken,
// a certificate that is still active and a policy that is still attached. It
// records every call, fails the methods named in fail, and pages the lists when
// pageSize is set.
type fakeIoT struct {
	mu       sync.Mutex
	calls    []string
	fail     map[string]error
	pageSize int
	seq      int

	policies map[string]*fakePolicy
	certs    map[string]*fakeCert
	attached map[string][]string // policy name -> certificate ARNs
}

type fakePolicy struct {
	arn      string
	tags     map[string]string
	versions []fakeVersion
}

type fakeVersion struct {
	id    string
	doc   string
	deflt bool
}

type fakeCert struct {
	arn, status string
}

const fakeAccount = "123456789012"

func newFakeIoT() *fakeIoT {
	return &fakeIoT{
		fail: map[string]error{}, policies: map[string]*fakePolicy{}, certs: map[string]*fakeCert{}, attached: map[string][]string{},
	}
}

func apiErr(code string) error { return &smithy.GenericAPIError{Code: code, Message: "fake " + code} }

// enter records a call and returns the error injected for its method.
func (f *fakeIoT) enter(call string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
	name, _, _ := strings.Cut(call, " ")
	return f.fail[name]
}

func (f *fakeIoT) joined() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return strings.Join(f.calls, "\n")
}

func (f *fakeIoT) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

// defaultDoc is the document of the policy's default version.
func (p *fakePolicy) defaultDoc() string {
	for _, v := range p.versions {
		if v.deflt {
			return v.doc
		}
	}
	return ""
}

func (f *fakeIoT) DescribeEndpoint(_ context.Context, in *iot.DescribeEndpointInput, _ ...func(*iot.Options)) (*iot.DescribeEndpointOutput, error) {
	if err := f.enter("DescribeEndpoint " + deref(in.EndpointType)); err != nil {
		return nil, err
	}
	if deref(in.EndpointType) != "iot:Data-ATS" {
		return nil, apiErr("InvalidRequestException")
	}
	addr := "abc123-ats.iot.eu-west-1.amazonaws.com"
	return &iot.DescribeEndpointOutput{EndpointAddress: &addr}, nil
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func (f *fakeIoT) CreateKeysAndCertificate(_ context.Context, in *iot.CreateKeysAndCertificateInput, _ ...func(*iot.Options)) (*iot.CreateKeysAndCertificateOutput, error) {
	if err := f.enter("CreateKeysAndCertificate active=" + strconv.FormatBool(in.SetAsActive)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seq++
	id := fmt.Sprintf("cert%04d", f.seq)
	arn := "arn:aws:iot:eu-west-1:" + fakeAccount + ":cert/" + id
	status := "INACTIVE"
	if in.SetAsActive {
		status = "ACTIVE"
	}
	f.certs[id] = &fakeCert{arn: arn, status: status}
	pem, key := "PEM-"+id, "KEY-"+id
	return &iot.CreateKeysAndCertificateOutput{
		CertificateArn: &arn, CertificateId: &id, CertificatePem: &pem, KeyPair: &types.KeyPair{PrivateKey: &key},
	}, nil
}

func (f *fakeIoT) DescribeCertificate(_ context.Context, in *iot.DescribeCertificateInput, _ ...func(*iot.Options)) (*iot.DescribeCertificateOutput, error) {
	if err := f.enter("DescribeCertificate " + deref(in.CertificateId)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.certs[deref(in.CertificateId)]; !ok {
		return nil, apiErr("ResourceNotFoundException")
	}
	pem := "PEM-" + deref(in.CertificateId)
	return &iot.DescribeCertificateOutput{CertificateDescription: &types.CertificateDescription{CertificatePem: &pem}}, nil
}

func (f *fakeIoT) UpdateCertificate(_ context.Context, in *iot.UpdateCertificateInput, _ ...func(*iot.Options)) (*iot.UpdateCertificateOutput, error) {
	if err := f.enter("UpdateCertificate " + deref(in.CertificateId) + " " + string(in.NewStatus)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.certs[deref(in.CertificateId)]
	if !ok {
		return nil, apiErr("ResourceNotFoundException")
	}
	c.status = string(in.NewStatus)
	return &iot.UpdateCertificateOutput{}, nil
}

func (f *fakeIoT) DeleteCertificate(_ context.Context, in *iot.DeleteCertificateInput, _ ...func(*iot.Options)) (*iot.DeleteCertificateOutput, error) {
	if err := f.enter("DeleteCertificate " + deref(in.CertificateId)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c, ok := f.certs[deref(in.CertificateId)]
	if !ok {
		return nil, apiErr("ResourceNotFoundException")
	}
	if c.status == "ACTIVE" {
		return nil, apiErr("CertificateStateException")
	}
	for _, arns := range f.attached {
		if slices.Contains(arns, c.arn) {
			return nil, apiErr("DeleteConflictException")
		}
	}
	delete(f.certs, deref(in.CertificateId))
	return &iot.DeleteCertificateOutput{}, nil
}

func (f *fakeIoT) CreatePolicy(_ context.Context, in *iot.CreatePolicyInput, _ ...func(*iot.Options)) (*iot.CreatePolicyOutput, error) {
	if err := f.enter("CreatePolicy " + deref(in.PolicyName)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	name := deref(in.PolicyName)
	if _, ok := f.policies[name]; ok {
		return nil, apiErr("ResourceAlreadyExistsException")
	}
	p := &fakePolicy{
		arn: "arn:aws:iot:eu-west-1:" + fakeAccount + ":policy/" + name, tags: map[string]string{},
		versions: []fakeVersion{{id: "1", doc: deref(in.PolicyDocument), deflt: true}},
	}
	for _, t := range in.Tags {
		p.tags[deref(t.Key)] = deref(t.Value)
	}
	f.policies[name] = p
	return &iot.CreatePolicyOutput{PolicyArn: &p.arn}, nil
}

func (f *fakeIoT) GetPolicy(_ context.Context, in *iot.GetPolicyInput, _ ...func(*iot.Options)) (*iot.GetPolicyOutput, error) {
	if err := f.enter("GetPolicy " + deref(in.PolicyName)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.policies[deref(in.PolicyName)]
	if !ok {
		return nil, apiErr("ResourceNotFoundException")
	}
	doc := p.defaultDoc()
	return &iot.GetPolicyOutput{PolicyArn: &p.arn, PolicyDocument: &doc}, nil
}

func (f *fakeIoT) DeletePolicy(_ context.Context, in *iot.DeletePolicyInput, _ ...func(*iot.Options)) (*iot.DeletePolicyOutput, error) {
	if err := f.enter("DeletePolicy " + deref(in.PolicyName)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	name := deref(in.PolicyName)
	p, ok := f.policies[name]
	if !ok {
		return nil, apiErr("ResourceNotFoundException")
	}
	if len(f.attached[name]) > 0 || len(p.versions) > 1 {
		return nil, apiErr("DeleteConflictException")
	}
	delete(f.policies, name)
	return &iot.DeletePolicyOutput{}, nil
}

func (f *fakeIoT) CreatePolicyVersion(_ context.Context, in *iot.CreatePolicyVersionInput, _ ...func(*iot.Options)) (*iot.CreatePolicyVersionOutput, error) {
	if err := f.enter("CreatePolicyVersion " + deref(in.PolicyName)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.policies[deref(in.PolicyName)]
	if !ok {
		return nil, apiErr("ResourceNotFoundException")
	}
	if len(p.versions) >= 5 {
		return nil, apiErr("VersionsLimitExceededException")
	}
	f.seq++
	if in.SetAsDefault {
		for i := range p.versions {
			p.versions[i].deflt = false
		}
	}
	p.versions = append(p.versions, fakeVersion{id: "v" + strconv.Itoa(f.seq), doc: deref(in.PolicyDocument), deflt: in.SetAsDefault})
	return &iot.CreatePolicyVersionOutput{}, nil
}

func (f *fakeIoT) ListPolicyVersions(_ context.Context, in *iot.ListPolicyVersionsInput, _ ...func(*iot.Options)) (*iot.ListPolicyVersionsOutput, error) {
	if err := f.enter("ListPolicyVersions " + deref(in.PolicyName)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.policies[deref(in.PolicyName)]
	if !ok {
		return nil, apiErr("ResourceNotFoundException")
	}
	out := &iot.ListPolicyVersionsOutput{}
	for _, v := range p.versions {
		id := v.id
		out.PolicyVersions = append(out.PolicyVersions, types.PolicyVersion{VersionId: &id, IsDefaultVersion: v.deflt})
	}
	return out, nil
}

func (f *fakeIoT) DeletePolicyVersion(_ context.Context, in *iot.DeletePolicyVersionInput, _ ...func(*iot.Options)) (*iot.DeletePolicyVersionOutput, error) {
	if err := f.enter("DeletePolicyVersion " + deref(in.PolicyName) + " " + deref(in.PolicyVersionId)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.policies[deref(in.PolicyName)]
	if !ok {
		return nil, apiErr("ResourceNotFoundException")
	}
	i := slices.IndexFunc(p.versions, func(v fakeVersion) bool { return v.id == deref(in.PolicyVersionId) })
	if i < 0 {
		return nil, apiErr("ResourceNotFoundException")
	}
	if p.versions[i].deflt {
		return nil, apiErr("InvalidRequestException")
	}
	p.versions = slices.Delete(p.versions, i, i+1)
	return &iot.DeletePolicyVersionOutput{}, nil
}

func (f *fakeIoT) AttachPolicy(_ context.Context, in *iot.AttachPolicyInput, _ ...func(*iot.Options)) (*iot.AttachPolicyOutput, error) {
	if err := f.enter("AttachPolicy " + deref(in.PolicyName) + " " + deref(in.Target)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	name, target := deref(in.PolicyName), deref(in.Target)
	if _, ok := f.policies[name]; !ok {
		return nil, apiErr("ResourceNotFoundException")
	}
	if !slices.ContainsFunc(slices.Collect(maps.Values(f.certs)), func(c *fakeCert) bool { return c.arn == target }) {
		return nil, apiErr("ResourceNotFoundException")
	}
	if !slices.Contains(f.attached[name], target) {
		f.attached[name] = append(f.attached[name], target)
	}
	return &iot.AttachPolicyOutput{}, nil
}

func (f *fakeIoT) DetachPolicy(_ context.Context, in *iot.DetachPolicyInput, _ ...func(*iot.Options)) (*iot.DetachPolicyOutput, error) {
	if err := f.enter("DetachPolicy " + deref(in.PolicyName) + " " + deref(in.Target)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	name, target := deref(in.PolicyName), deref(in.Target)
	i := slices.Index(f.attached[name], target)
	if i < 0 {
		return nil, apiErr("ResourceNotFoundException")
	}
	f.attached[name] = slices.Delete(f.attached[name], i, i+1)
	return &iot.DetachPolicyOutput{}, nil
}

// page returns the items of one page of a list and the token of the next page,
// "" at the end.
func page[T any](items []T, token string, size int) ([]T, string) {
	start, _ := strconv.Atoi(token)
	if size <= 0 || start+size >= len(items) {
		return items[min(start, len(items)):], ""
	}
	return items[start : start+size], strconv.Itoa(start + size)
}

func tokenPtr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

func (f *fakeIoT) ListTargetsForPolicy(_ context.Context, in *iot.ListTargetsForPolicyInput, _ ...func(*iot.Options)) (*iot.ListTargetsForPolicyOutput, error) {
	if err := f.enter("ListTargetsForPolicy " + deref(in.PolicyName)); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	targets := slices.Clone(f.attached[deref(in.PolicyName)])
	// Not everything attached to a policy is a certificate.
	targets = append(targets, "us-east-1:00000000-0000-0000-0000-000000000000")
	items, next := page(targets, deref(in.Marker), f.pageSize)
	return &iot.ListTargetsForPolicyOutput{Targets: items, NextMarker: tokenPtr(next)}, nil
}

func (f *fakeIoT) ListTagsForResource(_ context.Context, in *iot.ListTagsForResourceInput, _ ...func(*iot.Options)) (*iot.ListTagsForResourceOutput, error) {
	if err := f.enter("ListTagsForResource"); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	var tags []types.Tag
	for _, p := range f.policies {
		if p.arn == deref(in.ResourceArn) {
			for k, v := range p.tags {
				tags = append(tags, types.Tag{Key: &k, Value: &v})
			}
		}
	}
	// A tag that is not the claim's comes first, so a page without the claim's.
	other, ov := "other", "x"
	tags = append([]types.Tag{{Key: &other, Value: &ov}}, tags...)
	items, next := page(tags, deref(in.NextToken), f.pageSize)
	return &iot.ListTagsForResourceOutput{Tags: items, NextToken: tokenPtr(next)}, nil
}

var _ iotcore.API = (*fakeIoT)(nil)
