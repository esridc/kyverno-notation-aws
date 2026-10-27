package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/registry"
	"github.com/google/go-containerregistry/pkg/v1/empty"
	gcrremote "github.com/google/go-containerregistry/pkg/v1/remote"
	notationutils "github.com/nirmata/kyverno-notation-verifier/kubenotation/utils"
	knvtypes "github.com/nirmata/kyverno-notation-verifier/pkg/types"
	"github.com/notaryproject/notation-core-go/signature/jws"
	"github.com/notaryproject/notation-go"
	"github.com/notaryproject/notation-go/dir"
	notationregistry "github.com/notaryproject/notation-go/registry"
	"github.com/notaryproject/notation-go/signer"
	"go.uber.org/zap"
	authv1 "k8s.io/api/authentication/v1"
	"oras.land/oras-go/v2/registry/remote"
)

func testSignedImageContract(t *testing.T) {
	api := newTestAPIServer(t, func(w http.ResponseWriter, r *http.Request) {
		review, err := decodeTestTokenReview(r)
		if err != nil {
			t.Errorf("decode TokenReview: %v", err)
			http.Error(w, "invalid review", http.StatusBadRequest)
			return
		}
		review.Status = authv1.TokenReviewStatus{
			Authenticated: review.Spec.Token == "scoped-token" && len(review.Spec.Audiences) == 1 && review.Spec.Audiences[0] == testAudience,
			User:          authv1.UserInfo{Username: testCaller},
			Audiences:     []string{testAudience},
		}
		writeTestJSON(t, w, review)
	})
	setTestKubeconfig(t, api.URL)

	registryHandler := registry.New(registry.Logger(log.New(io.Discard, "", 0)), registry.WithReferrersSupport(true))
	localRegistry := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, password, ok := r.BasicAuth()
		if !ok || user != "fixture-user" || password != "fixture-password" {
			w.Header().Set("WWW-Authenticate", `Basic realm="local-fixture"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		registryHandler.ServeHTTP(w, r)
	}))
	defer localRegistry.Close()
	host := strings.TrimPrefix(localRegistry.URL, "https://")
	transport := localRegistry.Client().Transport
	oldHTTP, oldGCR := http.DefaultTransport, gcrremote.DefaultTransport
	http.DefaultTransport = fixtureOnlyTransport{transport, host, strings.TrimPrefix(api.URL, "http://")}
	gcrremote.DefaultTransport = http.DefaultTransport
	defer func() {
		http.DefaultTransport, gcrremote.DefaultTransport = oldHTTP, oldGCR
	}()

	trustedSigner, root := newTestSigner(t, "trusted-signer")
	foreignSigner, _ := newTestSigner(t, "foreign-signer")
	store := filepath.Join(dir.UserConfigDir, dir.X509TrustStoreDir("ca", "fixture"))
	requireTestNoError(t, os.MkdirAll(store, 0700))
	requireTestNoError(t, os.WriteFile(filepath.Join(store, "root.pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: root.Raw}), 0600))
	requireTestNoError(t, os.WriteFile(filepath.Join(notationutils.NotationPath, "strict.json"), []byte(testPolicyDocument("fixture", "x509.subject: CN=trusted-signer,O=Fixture,ST=Test,C=US")), 0600))
	requireTestNoError(t, os.WriteFile(filepath.Join(notationutils.NotationPath, "wrong-identity.json"), []byte(testPolicyDocument("fixture", "x509.subject: CN=someone-else,O=Fixture,ST=Test,C=US")), 0600))

	authenticator := authn.FromConfig(authn.AuthConfig{Username: "fixture-user", Password: "fixture-password"})
	for _, tt := range []struct {
		repository string
		signer     notation.Signer
	}{
		{"signed", trustedSigner},
		{"unsigned", nil},
		{"untrusted", foreignSigner},
	} {
		ref, err := name.NewTag(host + "/fixtures/" + tt.repository + ":test")
		requireTestNoError(t, err)
		requireTestNoError(t, gcrremote.Write(ref, empty.Image, gcrremote.WithAuth(authenticator)))
		if tt.signer == nil {
			continue
		}
		repository, err := remote.NewRepository(ref.Name())
		requireTestNoError(t, err)
		repository.Client = localRegistry.Client()
		// The fixture's signing client supplies only synthetic local credentials.
		repository.Client = basicAuthClient{repository.Client}
		_, err = notation.Sign(context.Background(), tt.signer, notationregistry.NewRepository(repository), notation.SignOptions{
			ArtifactReference: ref.Name(),
			SignerSignOptions: notation.SignerSignOptions{SignatureMediaType: jws.MediaTypeEnvelope},
		})
		requireTestNoError(t, err)
	}

	provider := &fixtureKeychain{registry: host}
	config := testVerifierConfig()
	config.tokenAudiences = tokenAudienceList{testAudience}
	config.providerKeychain = provider
	verifier := newImageVerifier(zap.NewNop().Sugar(), config)
	digest, err := empty.Image.Digest()
	requireTestNoError(t, err)
	for _, tt := range []struct {
		name       string
		repository string
		policy     string
		wantStatus int
		wantError  string
	}{
		{"trusted signature", "signed", "strict", http.StatusOK, ""},
		{"unsigned image denied", "unsigned", "strict", http.StatusNotAcceptable, "no signature"},
		{"untrusted signer denied", "untrusted", "strict", http.StatusNotAcceptable, "does not contain any trusted certificate"},
		{"wrong signing identity denied", "signed", "wrong-identity", http.StatusNotAcceptable, "trusted identities"},
		{"unknown trust policy denied", "signed", "missing", http.StatusNotAcceptable, "no trust policy found"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"trustPolicy":%q,"images":{"containers":{"app":{"registry":%q,"path":%q,"name":%q,"tag":"test","jsonPointer":"/spec/containers/0/image"}}}}`,
				tt.policy, host, "fixtures/"+tt.repository, tt.repository)
			request := httptest.NewRequest(http.MethodPost, "/checkimages", strings.NewReader(body))
			request.Header.Set("Authorization", "Bearer scoped-token")
			response := httptest.NewRecorder()
			verifier.HandleCheckImages(response, request)
			if response.Code != tt.wantStatus {
				t.Fatalf("got status %d, want %d: %s", response.Code, tt.wantStatus, response.Body)
			}
			if tt.wantStatus != http.StatusOK {
				if !strings.Contains(strings.ToLower(response.Body.String()), tt.wantError) {
					t.Fatalf("expected verification error containing %q, got %s", tt.wantError, response.Body)
				}
				return
			}
			var result knvtypes.ResponseData
			requireTestNoError(t, json.Unmarshal(response.Body.Bytes(), &result))
			if !result.Verified || len(result.Results) != 1 {
				t.Fatalf("unexpected verification result: %+v", result)
			}
			patch := result.Results[0]
			want := host + "/fixtures/signed@" + digest.String()
			if patch.Operation != "replace" || patch.Path != "/spec/containers/0/image" || patch.Value != want {
				t.Fatalf("unexpected digest mutation: %+v, want %q", patch, want)
			}
		})
	}
	if provider.calls.Load() == 0 {
		t.Fatal("verifier did not resolve credentials through the configured provider keychain")
	}
}

type fixtureOnlyTransport struct {
	base    http.RoundTripper
	host    string
	apiHost string
}

func (t fixtureOnlyTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Host != t.host && r.URL.Host != t.apiHost {
		return nil, fmt.Errorf("test blocked non-fixture network request to %s", r.URL.Host)
	}
	return t.base.RoundTrip(r)
}

type basicAuthClient struct {
	base remote.Client
}

func (c basicAuthClient) Do(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.SetBasicAuth("fixture-user", "fixture-password")
	return c.base.Do(r)
}

type fixtureKeychain struct {
	registry string
	calls    atomic.Int64
}

func (k *fixtureKeychain) Resolve(resource authn.Resource) (authn.Authenticator, error) {
	if resource.RegistryStr() != k.registry {
		return nil, fmt.Errorf("unexpected registry credential request: %s", resource.RegistryStr())
	}
	k.calls.Add(1)
	return authn.FromConfig(authn.AuthConfig{Username: "fixture-user", Password: "fixture-password"}), nil
}

func newTestSigner(t *testing.T, commonName string) (notation.Signer, *x509.Certificate) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	requireTestNoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: commonName + "-root"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	requireTestNoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	requireTestNoError(t, err)
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	requireTestNoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Fixture"}, Province: []string{"Test"}, Country: []string{"US"}},
		NotBefore:    root.NotBefore, NotAfter: root.NotAfter,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	requireTestNoError(t, err)
	leaf, err := x509.ParseCertificate(leafDER)
	requireTestNoError(t, err)
	signer, err := signer.NewGenericSigner(leafKey, []*x509.Certificate{leaf, root})
	requireTestNoError(t, err)
	return signer, root
}
