// Copyright 2022 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package v1alpha1

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"testing"

	"github.com/sigstore/policy-controller/test"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"knative.dev/pkg/apis"
)

// validRepository is a TUF repository that's been tarred, gzipped and base64
// encoded. These are vars because conversion to []byte seems to make them not
// constant
var (
	validRepository = `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`

	// This is valid base64 (hello world), but should not be able to gunzip
	// untar.
	invalidRepository = []byte(`aGVsbG8gd29ybGQK`)

	// TUF Root json, generated via scaffolding
	// IMPORTANT: The next expiration is on '2027-01-20T10:22:51Z'
	// Steps to generate:
	// 1. cgit clone github.com/sigstore/scaffolding
	// 2. run ./hack/setup-kind.sh
	// 3. export KO_DOCKER_REPO=registry.local:5001/sigstore
	// 4. run ./hack/setup-scaffolding.sh
	// 5. get the secrets from the kind cluster
	//    kubectl get secrets -o yaml -n tuf-system tuf-root
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI3LTAxLTIwVDEwOjIyOjUxWiIsCiAgImtleXMiOiB7CiAgICI2ZjAyZWM1YTQ3YWMwMWEyZjViN2RjZmU4MzUzZWMxMzY5M2MyMThmNTIyNDM4MTNhOGE3MjA0Y2UyNTdkZTE0IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICIyMTYzNTg5ODAzMzM1Zjg3MWRmZTlkNzVmY2EzOGMwY2UxOTA0MTUyZDVmMTA2N2M1ZjBmMjAxNmIyMzk3ZWY5IgogICAgfQogICB9LAogICAiNzA0ZDc4NTZjNzQ4Y2FhYzA1NjkzZTY4ZDBkNWU0NDJjODY4OGJhNmIyN2QzMjM4ZmVhY2NhODY5OTIwOTIxOCI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiNGI2ZmY2YjczNDkwZWIwNjgyNTRjYjU0YzNmYzhiMTI1MmQ2YzZiMGJlMDc5ZjMzODkyNWU3M2IwZWI5YzQxZiIKICAgIH0KICAgfSwKICAgIjczMDUwYzUyNTZmMjlmOTg4MWRkMDg4MWUxMDNlZDBlNjAzZDdmMGJmZjliZWMxYmI3MDViNTcxMTMwMGMwZDUiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjM0NDU2NGYyY2EyYTZkODQyMmY2Y2ZjNDcxYjE0Yjg3YWU1YjViMTM4NzY3NDAxOTJhNzQ4YmRhMzA2NWY4MjEiCiAgICB9CiAgIH0sCiAgICI4YTBlMTU4YTk2NTM0ZTlkNTljMjUxNmQ5NDQ1ZDY3YjhiZmVhMGYwZDVjZjcyM2RjMTMyNGIzMDM2YjdiYjMyIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICIwNGY3ZDZmOGE0ODJhZTNjOGMxODk4MTVlNDUxMGMxMWVmNDNmZWEwNTNlMmYwMDAwN2E0MjYzNDViOTQwYzkzIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiNmYwMmVjNWE0N2FjMDFhMmY1YjdkY2ZlODM1M2VjMTM2OTNjMjE4ZjUyMjQzODEzYThhNzIwNGNlMjU3ZGUxNCIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICI4YTBlMTU4YTk2NTM0ZTlkNTljMjUxNmQ5NDQ1ZDY3YjhiZmVhMGYwZDVjZjcyM2RjMTMyNGIzMDM2YjdiYjMyIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiNzA0ZDc4NTZjNzQ4Y2FhYzA1NjkzZTY4ZDBkNWU0NDJjODY4OGJhNmIyN2QzMjM4ZmVhY2NhODY5OTIwOTIxOCIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiNzMwNTBjNTI1NmYyOWY5ODgxZGQwODgxZTEwM2VkMGU2MDNkN2YwYmZmOWJlYzFiYjcwNWI1NzExMzAwYzBkNSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IHRydWUKIH0sCiAic2lnbmF0dXJlcyI6IFsKICB7CiAgICJrZXlpZCI6ICI2ZjAyZWM1YTQ3YWMwMWEyZjViN2RjZmU4MzUzZWMxMzY5M2MyMThmNTIyNDM4MTNhOGE3MjA0Y2UyNTdkZTE0IiwKICAgInNpZyI6ICJlOTE5OGU0OWZiNTE5MjQ1YjRkZTA5ZTZlMDM5ZDg2ODIwNTBjNWVjNjdkMzgzZWI3OWMwNGM5ZGIzM2ViMzllMmJjOWI5MWRmYWU4OWE2NWFhN2QyYjk4ZjQzMzc4MDhmZWU1ZWVmZjRlNmIyMTQ3NGRiMjQzNzdmNGE1Y2UwZCIKICB9CiBdCn0=`
)

func TestTrustRootValidation(t *testing.T) {
	rootJSONDecoded, err := base64.StdEncoding.DecodeString(rootJSON)
	if err != nil {
		t.Fatalf("Failed to decode rootJSON for testing: %v", err)
	}
	validRepositoryDecoded, err := base64.StdEncoding.DecodeString(validRepository)
	if err != nil {
		t.Fatalf("Failed to decode validRepository for testing: %v", err)
	}
	tests := []struct {
		name        string
		trustroot   TrustRoot
		errorString string
	}{{
		name: "Should work with a valid repository",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSONDecoded,
					MirrorFS: validRepositoryDecoded,
					Targets:  "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.root",
		errorString: "missing field(s): spec.repository.root",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					MirrorFS: validRepositoryDecoded,
					Targets:  "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.repository",
		errorString: "missing field(s): spec.repository.repository",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:    rootJSONDecoded,
					Targets: "targets",
				},
			},
		},
	}, {
		name:        "Should fail with a missing repository.targets",
		errorString: "missing field(s): spec.repository.targets",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSONDecoded,
					MirrorFS: validRepositoryDecoded,
				},
			},
		},
	}, {
		name:        "Should fail with an invalid repository.mirrorFS, not a gzip/tar file",
		errorString: "invalid value: failed to construct a TUF client: spec.repository.mirrorFS\nfailed to uncompress: gzip: invalid header",
		trustroot: TrustRoot{
			Spec: TrustRootSpec{
				Repository: &Repository{
					Root:     rootJSONDecoded,
					MirrorFS: invalidRepository,
					Targets:  "targets",
				},
			},
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := test.trustroot.Validate(context.TODO())
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestTimeStampAuthorityValidation(t *testing.T) {
	rootCert, rootKey, _ := test.GenerateRootCa()
	subCert, subKey, _ := test.GenerateSubordinateCa(rootCert, rootKey)
	leafCert, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert, subKey)
	rootCert2, rootKey2, _ := test.GenerateRootCa()
	subCert2, subKey2, _ := test.GenerateSubordinateCa(rootCert2, rootKey2)
	leafCert2, _, _ := test.GenerateLeafCert("subject", "oidc-issuer", subCert2, subKey2)

	pem, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{rootCert, subCert, leafCert})
	if err != nil {
		t.Fatalf("unexpected error marshalling certificates to PEM: %v", err)
	}
	tooManyLeavesPem, err := cryptoutils.MarshalCertificatesToPEM([]*x509.Certificate{rootCert, subCert, leafCert, leafCert2})
	if err != nil {
		t.Fatalf("unexpected error marshalling certificates to PEM: %v", err)
	}

	tests := []struct {
		name        string
		tsa         CertificateAuthority
		errorString string
	}{{
		name: "Should work with a valid repository",
		tsa: CertificateAuthority{
			Subject: DistinguishedName{
				Organization: "fulcio-organization",
				CommonName:   "fulcio-common-name",
			},
			URI:       *apis.HTTPS("fulcio.example.com"),
			CertChain: pem,
		},
	}, {
		name:        "Should fail splitting the certificates of the certChain",
		errorString: "invalid value: error splitting the certificates: certChain\nerror during PEM decoding",
		tsa: CertificateAuthority{
			Subject: DistinguishedName{
				Organization: "fulcio-organization",
				CommonName:   "fulcio-common-name",
			},
			URI:       *apis.HTTPS("fulcio.example.com"),
			CertChain: []byte("INVALID"),
		},
	}, {
		name:        "Should fail with a must contain at most one TSA certificate",
		errorString: "invalid value: certificate chain must contain at most one TSA certificate: certChain",
		tsa: CertificateAuthority{
			Subject: DistinguishedName{
				Organization: "fulcio-organization",
				CommonName:   "fulcio-common-name",
			},
			URI:       *apis.HTTPS("fulcio.example.com"),
			CertChain: tooManyLeavesPem,
		},
	}}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := ValidateTimeStampAuthority(context.TODO(), test.tsa)
			validateError(t, test.errorString, "", err)
		})
	}
}

func TestIgnoreStatusUpdatesTrustRoot(t *testing.T) {
	tr := &TrustRoot{Spec: TrustRootSpec{}}

	if err := tr.Validate(apis.WithinSubResourceUpdate(context.Background(), &tr, "status")); err != nil {
		t.Errorf("Failed to update status on invalid resource: %v", err)
	}
}
