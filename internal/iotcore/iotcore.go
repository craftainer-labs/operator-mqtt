// Package iotcore is the operator's client of AWS IoT Core: what an MqttUser on
// an AWS broker is made of. A user is one IoT policy (named by the claim, with
// the ownership tag) and the device certificates attached to it; the policy
// lets the certificate connect with one client id and use the tenant's topics
// (ADR 0002, section 16.5 of lib-operator-go). There is no Thing.
//
// Every error is classified into one of the Err values below, wrapping the
// SDK's own error, so a caller can tell a missing object from a refused
// credential from an unreachable API without reading the cloud's words.
package iotcore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/arn"
	"github.com/aws/aws-sdk-go-v2/service/iot"
	"github.com/aws/aws-sdk-go-v2/service/iot/types"
	"github.com/aws/smithy-go"
)

// ClaimTag is the tag of the IoT policy that names the claim that made it,
// namespace/name/uid.
const ClaimTag = "craftainer.dev/claim"

// endpointType is the data endpoint DescribeEndpoint is asked for: the one
// whose certificate chains to the Amazon Trust Services roots.
const endpointType = "iot:Data-ATS"

// The kinds of failure.
var (
	// ErrNotFound means the object is not there.
	ErrNotFound = errors.New("the IoT object does not exist")
	// ErrExists means an object of that name exists.
	ErrExists = errors.New("an IoT object of that name exists")
	// ErrDenied means the cloud refused the operator's credentials or its
	// permissions.
	ErrDenied = errors.New("the cloud refused the operator's credentials")
	// ErrAPI means the cloud reported an error, or answered with something
	// unusable.
	ErrAPI = errors.New("the IoT API reported an error")
	// ErrUnavailable means the API did not answer: a connection that failed or
	// was refused by the egress policy, or a timeout.
	ErrUnavailable = errors.New("the IoT API could not be reached")
	// ErrInvalidTopic means a topic cannot be written into an IoT policy
	// without widening it.
	ErrInvalidTopic = errors.New("a topic cannot be used in an IoT policy")
	// ErrBadARN means an ARN is not that of an IoT object.
	ErrBadARN = errors.New("not an IoT ARN")
)

// API is the part of the IoT client the package uses; *iot.Client implements
// it, and tests replace it.
type API interface {
	DescribeEndpoint(ctx context.Context, in *iot.DescribeEndpointInput, opts ...func(*iot.Options)) (*iot.DescribeEndpointOutput, error)
	CreateKeysAndCertificate(ctx context.Context, in *iot.CreateKeysAndCertificateInput, opts ...func(*iot.Options)) (*iot.CreateKeysAndCertificateOutput, error)
	DescribeCertificate(ctx context.Context, in *iot.DescribeCertificateInput, opts ...func(*iot.Options)) (*iot.DescribeCertificateOutput, error)
	UpdateCertificate(ctx context.Context, in *iot.UpdateCertificateInput, opts ...func(*iot.Options)) (*iot.UpdateCertificateOutput, error)
	DeleteCertificate(ctx context.Context, in *iot.DeleteCertificateInput, opts ...func(*iot.Options)) (*iot.DeleteCertificateOutput, error)
	CreatePolicy(ctx context.Context, in *iot.CreatePolicyInput, opts ...func(*iot.Options)) (*iot.CreatePolicyOutput, error)
	GetPolicy(ctx context.Context, in *iot.GetPolicyInput, opts ...func(*iot.Options)) (*iot.GetPolicyOutput, error)
	DeletePolicy(ctx context.Context, in *iot.DeletePolicyInput, opts ...func(*iot.Options)) (*iot.DeletePolicyOutput, error)
	CreatePolicyVersion(ctx context.Context, in *iot.CreatePolicyVersionInput, opts ...func(*iot.Options)) (*iot.CreatePolicyVersionOutput, error)
	ListPolicyVersions(ctx context.Context, in *iot.ListPolicyVersionsInput, opts ...func(*iot.Options)) (*iot.ListPolicyVersionsOutput, error)
	DeletePolicyVersion(ctx context.Context, in *iot.DeletePolicyVersionInput, opts ...func(*iot.Options)) (*iot.DeletePolicyVersionOutput, error)
	AttachPolicy(ctx context.Context, in *iot.AttachPolicyInput, opts ...func(*iot.Options)) (*iot.AttachPolicyOutput, error)
	DetachPolicy(ctx context.Context, in *iot.DetachPolicyInput, opts ...func(*iot.Options)) (*iot.DetachPolicyOutput, error)
	ListTargetsForPolicy(ctx context.Context, in *iot.ListTargetsForPolicyInput, opts ...func(*iot.Options)) (*iot.ListTargetsForPolicyOutput, error)
	ListTagsForResource(ctx context.Context, in *iot.ListTagsForResourceInput, opts ...func(*iot.Options)) (*iot.ListTagsForResourceOutput, error)
}

var _ API = (*iot.Client)(nil)

// Client is the IoT operations of the operator.
type Client struct{ api API }

// New returns a Client of an IoT API.
func New(api API) *Client { return &Client{api: api} }

// classify wraps an SDK error in the Err value of its kind. An error that is
// not the API's answer (no smithy.APIError in it) never reached the API.
func classify(err error) error {
	if err == nil {
		return nil
	}
	var api smithy.APIError
	if !errors.As(err, &api) {
		return fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	switch api.ErrorCode() {
	case "ResourceNotFoundException":
		return fmt.Errorf("%w: %w", ErrNotFound, err)
	case "ResourceAlreadyExistsException":
		return fmt.Errorf("%w: %w", ErrExists, err)
	case "AccessDeniedException", "UnauthorizedException", "UnrecognizedClientException",
		"InvalidSignatureException", "ExpiredTokenException":
		return fmt.Errorf("%w: %w", ErrDenied, err)
	}
	return fmt.Errorf("%w: %w", ErrAPI, err)
}

// missing reports a classified error that says the object is not there.
func missing(err error) bool { return errors.Is(err, ErrNotFound) }

// Endpoint returns the account's IoT data endpoint host name.
func (c *Client) Endpoint(ctx context.Context) (string, error) {
	out, err := c.api.DescribeEndpoint(ctx, &iot.DescribeEndpointInput{EndpointType: aws.String(endpointType)})
	if err != nil {
		return "", classify(err)
	}
	if aws.ToString(out.EndpointAddress) == "" {
		return "", fmt.Errorf("%w: no endpoint address", ErrAPI)
	}
	return *out.EndpointAddress, nil
}

// Cert is a device certificate and its private key, which AWS returns once.
// Printing a Cert never shows the key.
type Cert struct {
	ARN string
	ID  string
	PEM string
	key string
}

// Key is the private key, PEM encoded.
func (c Cert) Key() string { return c.key }

// String lists the certificate's identity, never the key.
func (c Cert) String() string { return "iotcore.Cert{" + c.ID + "}" }

// GoString is String, for %#v.
func (c Cert) GoString() string { return c.String() }

// NewCert makes a key pair and a certificate. The certificate is INACTIVE
// until Activate, so a certificate that never gets attached grants nothing.
func (c *Client) NewCert(ctx context.Context) (Cert, error) {
	out, err := c.api.CreateKeysAndCertificate(ctx, &iot.CreateKeysAndCertificateInput{SetAsActive: false})
	if err != nil {
		return Cert{}, classify(err)
	}
	if out.KeyPair == nil || aws.ToString(out.CertificateArn) == "" || aws.ToString(out.CertificateId) == "" ||
		aws.ToString(out.CertificatePem) == "" || aws.ToString(out.KeyPair.PrivateKey) == "" {
		return Cert{}, fmt.Errorf("%w: an incomplete certificate", ErrAPI)
	}
	return Cert{ARN: *out.CertificateArn, ID: *out.CertificateId, PEM: *out.CertificatePem, key: *out.KeyPair.PrivateKey}, nil
}

// Activate attaches the policy to the certificate and then makes it ACTIVE, so
// the certificate never works without its policy.
func (c *Client) Activate(ctx context.Context, policy string, cert Cert) error {
	if _, err := c.api.AttachPolicy(ctx, &iot.AttachPolicyInput{PolicyName: aws.String(policy), Target: aws.String(cert.ARN)}); err != nil {
		return classify(err)
	}
	_, err := c.api.UpdateCertificate(ctx, &iot.UpdateCertificateInput{CertificateId: aws.String(cert.ID), NewStatus: types.CertificateStatusActive})
	return classify(err)
}

// CertPEM returns the PEM of a certificate.
func (c *Client) CertPEM(ctx context.Context, id string) (string, error) {
	out, err := c.api.DescribeCertificate(ctx, &iot.DescribeCertificateInput{CertificateId: aws.String(id)})
	if err != nil {
		return "", classify(err)
	}
	if out.CertificateDescription == nil {
		return "", fmt.Errorf("%w: no certificate description", ErrAPI)
	}
	return aws.ToString(out.CertificateDescription.CertificatePem), nil
}

// CertID returns the certificate ID of a certificate ARN, "" for anything else
// (an empty string, the claim's placeholder, a Cognito identity).
func CertID(certARN string) string {
	a, err := arn.Parse(certARN)
	id, ok := strings.CutPrefix(a.Resource, "cert/")
	if err != nil || a.Service != "iot" || !ok {
		return ""
	}
	return id
}

// Retire ends a certificate: INACTIVE first, so it stops working at once, then
// detached from the policy (when one is named) and deleted. What is already
// gone is not an error.
func (c *Client) Retire(ctx context.Context, policy, certARN string) error {
	id := CertID(certARN)
	if id == "" {
		return ErrBadARN
	}
	_, err := c.api.UpdateCertificate(ctx, &iot.UpdateCertificateInput{CertificateId: aws.String(id), NewStatus: types.CertificateStatusInactive})
	if err = classify(err); err != nil {
		if missing(err) {
			return nil
		}
		return err
	}
	if policy != "" {
		_, err = c.api.DetachPolicy(ctx, &iot.DetachPolicyInput{PolicyName: aws.String(policy), Target: aws.String(certARN)})
		if err = classify(err); err != nil && !missing(err) {
			return err
		}
	}
	_, err = c.api.DeleteCertificate(ctx, &iot.DeleteCertificateInput{CertificateId: aws.String(id)})
	if err = classify(err); err != nil && !missing(err) {
		return err
	}
	return nil
}

// State is what Observe read of a user's policy.
type State struct {
	// Exists is false when there is no policy of the name.
	Exists bool
	// PolicyARN, Document and Claim are the policy's ARN, its default version's
	// document and the value of its ClaimTag ("" when it has none).
	PolicyARN string
	Document  string
	Claim     string
	// Certs are the ARNs of the certificates attached to the policy.
	Certs []string
}

// Observe reads the policy of a name, its tag and the certificates attached.
func (c *Client) Observe(ctx context.Context, name string) (State, error) {
	p, err := c.api.GetPolicy(ctx, &iot.GetPolicyInput{PolicyName: aws.String(name)})
	if err = classify(err); err != nil {
		if missing(err) {
			return State{}, nil
		}
		return State{}, err
	}
	st := State{Exists: true, PolicyARN: aws.ToString(p.PolicyArn), Document: aws.ToString(p.PolicyDocument)}
	var token *string
	for {
		out, err := c.api.ListTagsForResource(ctx, &iot.ListTagsForResourceInput{ResourceArn: p.PolicyArn, NextToken: token})
		if err != nil {
			return State{}, classify(err)
		}
		for _, t := range out.Tags {
			if aws.ToString(t.Key) == ClaimTag {
				st.Claim = aws.ToString(t.Value)
			}
		}
		if token = out.NextToken; aws.ToString(token) == "" {
			break
		}
	}
	var marker *string
	for {
		out, err := c.api.ListTargetsForPolicy(ctx, &iot.ListTargetsForPolicyInput{PolicyName: aws.String(name), Marker: marker})
		if err != nil {
			return State{}, classify(err)
		}
		for _, t := range out.Targets {
			if CertID(t) != "" {
				st.Certs = append(st.Certs, t)
			}
		}
		if marker = out.NextMarker; aws.ToString(marker) == "" {
			break
		}
	}
	return st, nil
}

// CreatePolicy makes the policy with the claim's tag. ErrExists means a policy
// of the name is there, whoever made it.
func (c *Client) CreatePolicy(ctx context.Context, name, claim, document string) error {
	_, err := c.api.CreatePolicy(ctx, &iot.CreatePolicyInput{
		PolicyName: aws.String(name), PolicyDocument: aws.String(document),
		Tags: []types.Tag{{Key: aws.String(ClaimTag), Value: aws.String(claim)}},
	})
	return classify(err)
}

// dropOldVersions deletes the policy's versions that are not the default, which
// a new version or the deletion of the policy needs (a policy has at most five).
func (c *Client) dropOldVersions(ctx context.Context, name string) error {
	out, err := c.api.ListPolicyVersions(ctx, &iot.ListPolicyVersionsInput{PolicyName: aws.String(name)})
	if err != nil {
		return classify(err)
	}
	for _, v := range out.PolicyVersions {
		if v.IsDefaultVersion {
			continue
		}
		_, err := c.api.DeletePolicyVersion(ctx, &iot.DeletePolicyVersionInput{PolicyName: aws.String(name), PolicyVersionId: v.VersionId})
		if err = classify(err); err != nil && !missing(err) {
			return err
		}
	}
	return nil
}

// SetDocument makes document the policy's default version.
func (c *Client) SetDocument(ctx context.Context, name, document string) error {
	if err := c.dropOldVersions(ctx, name); err != nil {
		return err
	}
	_, err := c.api.CreatePolicyVersion(ctx, &iot.CreatePolicyVersionInput{
		PolicyName: aws.String(name), PolicyDocument: aws.String(document), SetAsDefault: true,
	})
	return classify(err)
}

// DeletePolicy deletes the policy with its old versions; one that is gone is
// not an error. Every certificate must be detached first.
func (c *Client) DeletePolicy(ctx context.Context, name string) error {
	if err := c.dropOldVersions(ctx, name); err != nil {
		if missing(err) {
			return nil
		}
		return err
	}
	_, err := c.api.DeletePolicy(ctx, &iot.DeletePolicyInput{PolicyName: aws.String(name)})
	if err = classify(err); err != nil && !missing(err) {
		return err
	}
	return nil
}

// SameDocument reports whether two policy documents say the same, whatever
// their spacing.
func SameDocument(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	return reflect.DeepEqual(x, y)
}

// Scope is where a user's IoT objects are: what the ARNs of a policy are made
// of.
type Scope struct{ Partition, Region, Account string }

// ScopeOf reads the scope from the ARN of an IoT object of the account (a
// certificate or a policy).
func ScopeOf(objectARN string) (Scope, error) {
	a, err := arn.Parse(objectARN)
	if err != nil || a.Service != "iot" || a.Region == "" || a.AccountID == "" {
		return Scope{}, ErrBadARN
	}
	return Scope{Partition: a.Partition, Region: a.Region, Account: a.AccountID}, nil
}
