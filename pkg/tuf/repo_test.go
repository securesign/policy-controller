// Copyright 2022 The Sigstore Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tuf

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"

	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/theupdateframework/go-tuf"
	"knative.dev/pkg/logging"
)

const (
	fulcioRootCert = `-----BEGIN CERTIFICATE-----
MIICNzCCAd2gAwIBAgITPLBoBQhl1hqFND9S+SGWbfzaRTAKBggqhkjOPQQDAjBo
MQswCQYDVQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlw
cGVuaGFtMQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMI
dGVzdGNlcnQwHhcNMjEwMzEyMjMyNDQ5WhcNMzEwMjI4MjMyNDQ5WjBoMQswCQYD
VQQGEwJVSzESMBAGA1UECBMJV2lsdHNoaXJlMRMwEQYDVQQHEwpDaGlwcGVuaGFt
MQ8wDQYDVQQKEwZSZWRIYXQxDDAKBgNVBAsTA0NUTzERMA8GA1UEAxMIdGVzdGNl
cnQwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQRn+Alyof6xP3GQClSwgV0NFuY
YEwmKP/WLWr/LwB6LUYzt5v49RlqG83KuaJSpeOj7G7MVABdpIZYWwqAiZV3o2Yw
ZDAOBgNVHQ8BAf8EBAMCAQYwEgYDVR0TAQH/BAgwBgEB/wIBATAdBgNVHQ4EFgQU
T8Jwm6JuVb0dsiuHUROiHOOVHVkwHwYDVR0jBBgwFoAUT8Jwm6JuVb0dsiuHUROi
HOOVHVkwCgYIKoZIzj0EAwIDSAAwRQIhAJkNZmP6sKA+8EebRXFkBa9DPjacBpTc
OljJotvKidRhAiAuNrIazKEw2G4dw8x1z6EYk9G+7fJP5m93bjm/JfMBtA==
-----END CERTIFICATE-----`

	ctlogPublicKey = `-----BEGIN RSA PUBLIC KEY-----
MIICCgKCAgEAu1Ah4n2P8JGt92Qg86FdR8f1pou43yndggMuRCX0JB+bLn1rUFRA
KQVd+xnnd4PXJLLdml8ZohCr0lhBuMxZ7zBzt0T98kblUCxBgABPNpWIkTgacyC8
MlIYY/yBSuDWAJOA5IKi4Hh9nI+Mmb/FXgbOz5a5mZx8w7pMiTMu0+Rd9cPzRkUZ
DQfZsLONr6PwmyCAIL1oK80fevxKZPME0UV8bFPWnRxeVaFr5ddd/DOenV8H6SPy
r4ODbSOItpl53y6Az0m3FTIUf8cSsyR7dfE4zpA3M4djjtoKDNFRsTjU2RWVQW9X
MaxzznGVGhLEwkC+sYjR5NQvH5iiRvV18q+CGQqNX2+WWM3SPuty3nc86RBNR0FO
gSQA0TL2OAs6bJNmfzcwZxAKYbj7/88tj6qrjLaQtFTbBm2a7+TAQfs3UTiQi00z
EDYqeSj2WQvacNm1dWEAyx0QNLHiKGTn4TShGj8LUoGyjJ26Y6VPsotvCoj8jM0e
aN8Pc9/AYywVI+QktjaPZa7KGH3XJHJkTIQQRcUxOtDstKpcriAefDs8jjL5ju9t
5J3qEvgzmclNJKRnla4p3maM0vk+8cC7EXMV4P1zuCwr3akaHFJo5Y0aFhKsnHqT
c70LfiFo//8/QsvyjLIUtEWHTkGeuf4PpbYXr5qpJ6tWhG2MARxdeg8CAwEAAQ==
-----END RSA PUBLIC KEY-----`

	rekorPublicKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEF6j2sTItLcs0wKoOpMzI+9lJmCzf
N6mY2prOeaBRV2dnsJzC94hOxkM5pSp9nbAK1TBOI45fOOPsH2rSR++HrA==
-----END PUBLIC KEY-----`

	// validRepository is a valid tar/gzipped repository representing an air-gap
	// TUF repository.
	validRepository = `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`

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

func TestCompressUncompressFS(t *testing.T) {
	files := map[string][]byte{
		"fulcio_v1.crt.pem": []byte(fulcioRootCert),
		"ctfe.pub":          []byte(ctlogPublicKey),
		"rekor.pub":         []byte(rekorPublicKey),
	}
	repo, dir, err := createRepo(context.Background(), files)
	if err != nil {
		t.Fatalf("Failed to CreateRepo: %s", err)
	}
	defer os.RemoveAll(dir)

	var buf bytes.Buffer
	fsys := os.DirFS(dir)
	if err = CompressFS(fsys, &buf, map[string]bool{"keys": true, "staged": true}); err != nil {
		t.Fatalf("Failed to compress: %v", err)
	}
	os.WriteFile("/tmp/newcompressed", buf.Bytes(), os.ModePerm)
	dstDir := t.TempDir()
	if err = Uncompress(&buf, dstDir); err != nil {
		t.Fatalf("Failed to uncompress: %v", err)
	}
	// Then check that files have been uncompressed there.
	meta, err := repo.GetMeta()
	if err != nil {
		t.Errorf("Failed to GetMeta: %s", err)
	}
	root := meta["root.json"]

	// This should have roundtripped to the new directory.
	rtRoot, err := os.ReadFile(filepath.Join(dstDir, "repository", "root.json"))
	if err != nil {
		t.Errorf("Failed to read the roundtripped root %v", err)
	}
	if !bytes.Equal(root, rtRoot) {
		t.Errorf("Roundtripped root differs:\n%s\n%s", string(root), string(rtRoot))
	}

	// As well as, say rekor.pub under targets dir
	rtRekor, err := os.ReadFile(filepath.Join(dstDir, "repository", "targets", "rekor.pub"))
	if err != nil {
		t.Errorf("Failed to read the roundtripped rekor %v", err)
	}
	if !bytes.Equal(files["rekor.pub"], rtRekor) {
		t.Errorf("Roundtripped rekor differs:\n%s\n%s", rekorPublicKey, string(rtRekor))
	}
}

func createRepo(ctx context.Context, files map[string][]byte) (tuf.LocalStore, string, error) {
	// TODO: Make this an in-memory fileystem.
	//	tmpDir := os.TempDir()
	//	dir := tmpDir + "tuf"
	dir := "/tmp/tuf"
	err := os.Mkdir(dir, os.ModePerm)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create tmp TUF dir: %w", err)
	}
	dir += "/"
	logging.FromContext(ctx).Infof("Creating the FS in %q", dir)
	local := tuf.FileSystemStore(dir, nil)

	// Create and commit a new TUF repo with the targets to the store.
	logging.FromContext(ctx).Infof("Creating new repo in %q", dir)
	r, err := tuf.NewRepoIndent(local, "", " ")
	if err != nil {
		return nil, "", fmt.Errorf("failed to NewRepoIndent: %w", err)
	}

	// Added by vaikas
	if err := r.Init(false); err != nil {
		return nil, "", fmt.Errorf("failed to Init repo: %w", err)
	}

	// Make all metadata files expire in 6 months.
	expires := time.Now().AddDate(0, 6, 0)

	for _, role := range []string{"root", "targets", "snapshot", "timestamp"} {
		_, err := r.GenKeyWithExpires(role, expires)
		if err != nil {
			return nil, "", fmt.Errorf("failed to GenKeyWithExpires: %w", err)
		}
	}

	targets := make([]string, 0, len(files))
	for k, v := range files {
		logging.FromContext(ctx).Infof("Adding %s file", k)
		if err := writeStagedTarget(dir, k, v); err != nil {
			return nil, "", fmt.Errorf("failed to write staged target %s: %w", k, err)
		}
		targets = append(targets, k)
	}
	err = r.AddTargetsWithExpires(targets, nil, expires)
	if err != nil {
		return nil, "", fmt.Errorf("failed to add AddTargetsWithExpires: %w", err)
	}

	// Snapshot, Timestamp, and Publish the repository.
	if err := r.SnapshotWithExpires(expires); err != nil {
		return nil, "", fmt.Errorf("failed to add SnapShotWithExpires: %w", err)
	}
	if err := r.TimestampWithExpires(expires); err != nil {
		return nil, "", fmt.Errorf("failed to add TimestampWithExpires: %w", err)
	}
	if err := r.Commit(); err != nil {
		return nil, "", fmt.Errorf("failed to Commit: %w", err)
	}
	return local, dir, nil
}

func writeStagedTarget(dir, path string, data []byte) error {
	path = filepath.Join(dir, "staged", "targets", path)
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func TestClientFromSerializedMirror(t *testing.T) {
	repo, err := base64.StdEncoding.DecodeString(validRepository)
	if err != nil {
		t.Fatalf("failed to decode validrepository: %v", err)
	}
	root, err := base64.StdEncoding.DecodeString(rootJSON)
	if err != nil {
		t.Fatalf("failed to decode rootJSON: %v", err)
	}
	tufClient, err := ClientFromSerializedMirror(context.Background(), repo, root, "targets", "/repository/")
	if err != nil {
		t.Fatalf("Failed to unserialize repo: %v", err)
	}
	targets, err := tufClient.Targets()
	if err != nil {
		t.Errorf("failed to get Targets from tuf: %v", err)
	}
	if len(targets) == 0 {
		t.Errorf("Got no targets from the TUF client")
	}
}

func TestClientFromRemoteMirror(t *testing.T) {
	files := map[string][]byte{
		"fulcio_v1.crt.pem": []byte(fulcioRootCert),
		"ctfe.pub":          []byte(ctlogPublicKey),
		"rekor.pub":         []byte(rekorPublicKey),
	}
	local, dir, err := createRepo(context.Background(), files)
	if err != nil {
		t.Fatalf("Failed to CreateRepo: %s", err)
	}
	defer os.RemoveAll(dir)
	meta, err := local.GetMeta()
	if err != nil {
		t.Fatalf("getting meta: %v", err)
	}
	rootJSON, ok := meta["root.json"]
	if !ok {
		t.Fatalf("Getting root: %v", err)
	}
	serveDir := filepath.Join(dir, "repository")
	t.Logf("tuf repository was created in: %s serving tuf root at %s", dir, serveDir)
	fs := http.FileServer(http.Dir(serveDir))
	http.Handle("/", fs)

	ts := httptest.NewServer(fs)
	defer ts.Close()

	tufClient, err := ClientFromRemote(context.Background(), ts.URL, rootJSON, "targets")
	if err != nil {
		t.Fatalf("Failed to get client from remote: %v", err)
	}
	targets, err := tufClient.Targets()
	if err != nil {
		t.Errorf("failed to get Targets from tuf: %v", err)
	}
	if len(targets) == 0 {
		t.Errorf("Got no targets from the TUF client")
	}
}
