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
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"
	"time"

	"github.com/theupdateframework/go-tuf"
	"github.com/theupdateframework/go-tuf/v2/metadata"
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

	// IMPORTANT: The next expiration is on '2027-01-20T10:10:45Z'
	// To regenerate: go run hack/gentestdata/gen_tuf_repo_test_data.go
	rootJSON = `ewogInNpZ25lZCI6IHsKICAiX3R5cGUiOiAicm9vdCIsCiAgInNwZWNfdmVyc2lvbiI6ICIxLjAiLAogICJ2ZXJzaW9uIjogMSwKICAiZXhwaXJlcyI6ICIyMDI3LTAxLTIwVDEwOjEwOjQ1WiIsCiAgImtleXMiOiB7CiAgICIyNzQ2OWE0MThiYzMxNzE2YzBkYTUzN2JjMjFhZjQ4Y2RhNzZhZTViYjMzM2U2ZTFhOTk0MTcwYmJmYjQ1OWIxIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJiNDMwZmU2ZjA2MDIxMmMyOWE1ZGMzYTdlOGNiYmU0OTQ2ZTBiYTAyN2FiMDRkZTgwNmFjYWRmNDA1YzMxOGYxIgogICAgfQogICB9LAogICAiNTI2OTNjN2ExNzFmNjFjZGU3MmNhZDFjZDhlMjM4MzBlZjc2ODVkN2FkNzFkOGU1NTFkNzZjODBlMjgyMjdlYyI6IHsKICAgICJrZXl0eXBlIjogImVkMjU1MTkiLAogICAgInNjaGVtZSI6ICJlZDI1NTE5IiwKICAgICJrZXlpZF9oYXNoX2FsZ29yaXRobXMiOiBbCiAgICAgInNoYTI1NiIsCiAgICAgInNoYTUxMiIKICAgIF0sCiAgICAia2V5dmFsIjogewogICAgICJwdWJsaWMiOiAiZTljOTkyNDg0ZDk2ODA4YTQ4ODJkZjUwYjk1YmY5MzBmZDRlZDZkOGZmMTg0YmFjOWNhMmY0Zjg1ZTkyN2YxYSIKICAgIH0KICAgfSwKICAgIjlmMmE0N2Y0MDFjYTUwMmIzYTE5NWEyM2E0ZmZmNmVkMGU2ZTA4YzEwOWVlMDAzNGE2NmQ0N2JmNTYxNGZjMTEiOiB7CiAgICAia2V5dHlwZSI6ICJlZDI1NTE5IiwKICAgICJzY2hlbWUiOiAiZWQyNTUxOSIsCiAgICAia2V5aWRfaGFzaF9hbGdvcml0aG1zIjogWwogICAgICJzaGEyNTYiLAogICAgICJzaGE1MTIiCiAgICBdLAogICAgImtleXZhbCI6IHsKICAgICAicHVibGljIjogIjllYmMwYTBmY2QyNjM1ZGVkZmVkZTY1NmY4Y2M4ZGMyYWVlMDRlZTdkYjY1MWMzYjM0NjkyY2QwZGRjMzgxM2QiCiAgICB9CiAgIH0sCiAgICJhOGE3NDRiNDY0OWM3YmQwMjdiMzBlMjllYjYzZWFiNWExZDE3Yjc5ZjUyODI4MzY0NjQ1YWIxNjQyOThiOWIzIjogewogICAgImtleXR5cGUiOiAiZWQyNTUxOSIsCiAgICAic2NoZW1lIjogImVkMjU1MTkiLAogICAgImtleWlkX2hhc2hfYWxnb3JpdGhtcyI6IFsKICAgICAic2hhMjU2IiwKICAgICAic2hhNTEyIgogICAgXSwKICAgICJrZXl2YWwiOiB7CiAgICAgInB1YmxpYyI6ICJjMGQxMGFhMWU2NzAxM2IyZDYzNDA3OTFlZWZhZTczZTgzYmRjMmE5Yzc3ZjM3M2IzZGNkNDk3Y2M2ZDdhNjYzIgogICAgfQogICB9CiAgfSwKICAicm9sZXMiOiB7CiAgICJyb290IjogewogICAgImtleWlkcyI6IFsKICAgICAiYThhNzQ0YjQ2NDljN2JkMDI3YjMwZTI5ZWI2M2VhYjVhMWQxN2I3OWY1MjgyODM2NDY0NWFiMTY0Mjk4YjliMyIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAic25hcHNob3QiOiB7CiAgICAia2V5aWRzIjogWwogICAgICI1MjY5M2M3YTE3MWY2MWNkZTcyY2FkMWNkOGUyMzgzMGVmNzY4NWQ3YWQ3MWQ4ZTU1MWQ3NmM4MGUyODIyN2VjIgogICAgXSwKICAgICJ0aHJlc2hvbGQiOiAxCiAgIH0sCiAgICJ0YXJnZXRzIjogewogICAgImtleWlkcyI6IFsKICAgICAiOWYyYTQ3ZjQwMWNhNTAyYjNhMTk1YTIzYTRmZmY2ZWQwZTZlMDhjMTA5ZWUwMDM0YTY2ZDQ3YmY1NjE0ZmMxMSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9LAogICAidGltZXN0YW1wIjogewogICAgImtleWlkcyI6IFsKICAgICAiMjc0NjlhNDE4YmMzMTcxNmMwZGE1MzdiYzIxYWY0OGNkYTc2YWU1YmIzMzNlNmUxYTk5NDE3MGJiZmI0NTliMSIKICAgIF0sCiAgICAidGhyZXNob2xkIjogMQogICB9CiAgfSwKICAiY29uc2lzdGVudF9zbmFwc2hvdCI6IHRydWUKIH0sCiAic2lnbmF0dXJlcyI6IFsKICB7CiAgICJrZXlpZCI6ICJhOGE3NDRiNDY0OWM3YmQwMjdiMzBlMjllYjYzZWFiNWExZDE3Yjc5ZjUyODI4MzY0NjQ1YWIxNjQyOThiOWIzIiwKICAgInNpZyI6ICIwZjNkNjg2MTczNDAxZmY3YTIyYjliNDRkMWM3ZWQyMDRiZGNhM2M3ZTgyOWQ4NjQ5NjJkZDMxNWJjMDQ1YTQ1MDExODg2MDBiZjY4OWY2Y2EyYzY1OTRmNGJhNDE1MDQ4N2ZlNDFkNDgwZWM1ZGM5OWFjMTM1ZjhiNTc1ZGEwMiIKICB9CiBdCn0=`
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

func TestFsFetcherNotFound(t *testing.T) {
	testFS := fstest.MapFS{
		"existing.json": &fstest.MapFile{Data: []byte(`{"hello":"world"}`)},
	}
	f := &fsFetcher{fsys: testFS, baseURL: "mem://test/"}

	// Existing file should succeed
	data, err := f.DownloadFile("mem://test/existing.json", 0, 0)
	if err != nil {
		t.Fatalf("unexpected error for existing file: %v", err)
	}
	if string(data) != `{"hello":"world"}` {
		t.Errorf("unexpected data: %s", data)
	}

	// Missing file should return ErrDownloadHTTP with 404
	_, err = f.DownloadFile("mem://test/missing.json", 0, 0)
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	var httpErr *metadata.ErrDownloadHTTP
	if !errors.As(err, &httpErr) || httpErr.StatusCode != 404 {
		t.Errorf("expected ErrDownloadHTTP{404}, got: %v", err)
	}
}

func TestFsFetcherMaxLength(t *testing.T) {
	testFS := fstest.MapFS{
		"big.json": &fstest.MapFile{Data: make([]byte, 100)},
	}
	f := &fsFetcher{fsys: testFS, baseURL: "mem://test/"}

	// Should succeed when maxLength is 0 (unlimited)
	_, err := f.DownloadFile("mem://test/big.json", 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should fail when file exceeds maxLength
	_, err = f.DownloadFile("mem://test/big.json", 50, 0)
	if err == nil {
		t.Fatal("expected error for oversized file")
	}
	var lenErr *metadata.ErrDownloadLengthMismatch
	if !errors.As(err, &lenErr) {
		t.Errorf("expected ErrDownloadLengthMismatch, got: %v", err)
	}
}

func TestDownloadTargetFromSerializedMirror(t *testing.T) {
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
		t.Fatalf("Failed to create client: %v", err)
	}

	// Download each target via GetTarget and verify it has content
	targets, err := tufClient.GetTopLevelTargets()
	if err != nil {
		t.Fatalf("GetTopLevelTargets error: %v", err)
	}
	for name := range targets {
		data, err := tufClient.GetTarget(name)
		if err != nil {
			t.Errorf("GetTarget(%s) error: %v", name, err)
			continue
		}
		if len(data) == 0 {
			t.Errorf("GetTarget(%s) returned empty data", name)
		}
	}
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
	targets, err := tufClient.GetTopLevelTargets()
	if err != nil {
		t.Fatalf("GetTopLevelTargets error: %v", err)
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
	targets, err := tufClient.GetTopLevelTargets()
	if err != nil {
		t.Fatalf("GetTopLevelTargets error: %v", err)
	}
	if len(targets) == 0 {
		t.Errorf("Got no targets from the TUF client")
	}
}
