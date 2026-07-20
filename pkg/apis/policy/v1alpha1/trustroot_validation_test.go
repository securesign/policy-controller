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
	// IMPORTANT: The next expiration is on '2027-01-20T12:00:41Z'
	// Steps to generate:
	// 1. cgit clone github.com/sigstore/scaffolding
	// 2. run ./hack/setup-kind.sh
	// 3. export KO_DOCKER_REPO=registry.local:5001/sigstore
	// 4. run ./hack/setup-scaffolding.sh
	// 5. get the secrets from the kind cluster
	//    kubectl get secrets -o yaml -n tuf-system tuf-root
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI3LTAxLTIwVDEyOjAwOjQxWiIsCiAgImtleXMiOiB7CiAgICIxYmRhZmE5ODI0MWY4Y2VmNmYzOGVjNDIyNWQxZWE5YTRmYTBhZjg0ZWFjOGU5NGVjYzQ0MDc3NWI4Y2Y5YjAxIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI3MWU5ZjdkM2NjYzAzMTJkNzBlYjE2NjEwNGY0MDgzYmZmZWNlYzFmMGFjYjJlOWE2ZDNmMWJhNmZmNTVjOWM0IgogICAgfQogICB9LAogICAiMmU3YzllYzg5MzU3Y2QxMjkyZTdmYmQ2ZWE4ZmI5NGRjN2RiMjMzZjkwMDdjMjRiNjViNDk4Mjk4NjU4OTgyMSI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiMjNjODM0MjVmNzdmZWM4YzUzOTNmYjBiODFjOThmZjFlMDJiZmRjNWI0MDdiNjQ2OTE1NDAzYzYxNTk0NDFjNCIKICAgIH0KICAgfSwKICAgIjMzODVhODZiYTk1NDJlNjgzNmUxNjJiNTlkZWRmZWI1ZTZhMGFkODlmNmM4YjljZGZlOTU1ZjhmZjJjZWEwZjYiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjA2ZGJiZTJkNzViZmEyZjhmNWY0YmIxODlhYWFlNmJjNjBmMTcwZDkwMzc4ZGJlNjZmNGM1NzAwZjUxYjZiMmUiCiAgICB9CiAgIH0sCiAgICI2MmNjMjMyYTYyMmEwMWUyOWI5YjQ2ODc3ZDE3OGEyNjBlM2FlOGUyMTI3YTAxMjQ0YjgxMzYzZTkwZTljNjY3IjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICI0MmVkZTUxMWY4ZDEzYTBmYTNlMTM1NjZlMWMzMmQyYzI2ZjQ1NmY1Zjk4ZGU0MjI5MTQxZTM4MjBjYjMyZGMzIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiMzM4NWE4NmJhOTU0MmU2ODM2ZTE2MmI1OWRlZGZlYjVlNmEwYWQ4OWY2YzhiOWNkZmU5NTVmOGZmMmNlYTBmNiIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICI2MmNjMjMyYTYyMmEwMWUyOWI5YjQ2ODc3ZDE3OGEyNjBlM2FlOGUyMTI3YTAxMjQ0YjgxMzYzZTkwZTljNjY3IgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiMmU3YzllYzg5MzU3Y2QxMjkyZTdmYmQ2ZWE4ZmI5NGRjN2RiMjMzZjkwMDdjMjRiNjViNDk4Mjk4NjU4OTgyMSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiMWJkYWZhOTgyNDFmOGNlZjZmMzhlYzQyMjVkMWVhOWE0ZmEwYWY4NGVhYzhlOTRlY2M0NDA3NzViOGNmOWIwMSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IHRydWUKIH0sCiAic2lnbmF0dXJlcyI6IFsKICB7CiAgICJrZXlpZCI6ICIzMzg1YTg2YmE5NTQyZTY4MzZlMTYyYjU5ZGVkZmViNWU2YTBhZDg5ZjZjOGI5Y2RmZTk1NWY4ZmYyY2VhMGY2IiwKICAgInNpZyI6ICI5OTBiZjAxNDY2ZWNjNDc4ZWVmODcxMmJmNDBjMWEzNmE4ODZiYzFkZTU3MGNmYTllNTkyODE3Njg5OTY3MjRmNjlkM2VlN2E3MmZjNjg1ODM4NjVlYTM5MGE3MWZlOGE2NjlkNzFkZDExNzY3Y2E2Y2JiNDVhYjk5NzYyMGMwMCIKICB9CiBdCn0=`
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
