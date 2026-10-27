package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	notationutils "github.com/nirmata/kyverno-notation-verifier/kubenotation/utils"
	"github.com/notaryproject/notation-go/dir"
	"go.uber.org/zap"
	authv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	clientcmd "k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
)

const (
	testAudience = "kyverno-svc.kyverno.io"
	testCaller   = "system:serviceaccount:kyverno:kyverno-admission-controller"
)

func TestTokenAudiencesFlag(t *testing.T) {
	for _, tt := range []struct {
		value string
		want  tokenAudienceList
	}{
		{"", nil},
		{testAudience, tokenAudienceList{testAudience}},
		{testAudience + ",second-audience", tokenAudienceList{testAudience, "second-audience"}},
	} {
		t.Run(tt.value, func(t *testing.T) {
			got := parseTestAudiences(t, tt.value)
			if !reflect.DeepEqual(got, tt.want) || got.String() != tt.value {
				t.Fatalf("parsed %q as %#v, want %#v", tt.value, got, tt.want)
			}
		})
	}
	for _, value := range []string{" ", ",", testAudience + ",", "," + testAudience, "a,,b", "a, b", "a\tb", "a\nb", "a\u00a0b", "a\u0085b"} {
		t.Run("invalid/"+value, func(t *testing.T) {
			var audiences tokenAudienceList
			if err := audiences.Set(value); err == nil {
				t.Fatalf("accepted malformed audiences %q", value)
			}
		})
	}
}

func parseTestAudiences(t *testing.T, value string) tokenAudienceList {
	t.Helper()
	var audiences tokenAudienceList
	flags := flag.NewFlagSet("verifier-test", flag.ContinueOnError)
	flags.Var(&audiences, "tokenAudiences", "")
	if value != "" {
		if err := flags.Parse([]string{"--tokenAudiences=" + value}); err != nil {
			t.Fatal(err)
		}
	}
	return audiences
}

func TestVerifierContract(t *testing.T) {
	// The library's Stop waits for informers before signalling them. A subprocess
	// owns their lifetime without altering the library or leaking into other tests.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestVerifierContractProcess$", "-test.v")
	cmd.Env = append(os.Environ(), "NOTATION_CONTRACT_PROCESS=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("verifier contract process failed: %v\n%s", err, output)
	}
}

func TestVerifierContractProcess(t *testing.T) {
	if os.Getenv("NOTATION_CONTRACT_PROCESS") != "1" {
		t.Skip("run through TestVerifierContract")
	}
	isolateVerifierFiles(t)
	tests := []struct {
		name       string
		audiences  string
		token      string
		username   string
		reviewErr  bool
		authHeader string
		wantBody   string
		wantReview bool
	}{
		{"scoped admission caller", testAudience, "scoped-token", testCaller, false, "Bearer scoped-token", "atleast one image must be provided", true},
		{"scoped reports caller", testAudience, "scoped-token", "system:serviceaccount:kyverno:kyverno-reports-controller", false, "Bearer scoped-token", "atleast one image must be provided", true},
		{"multiple configured audiences", "other-audience," + testAudience, "scoped-token", testCaller, false, "Bearer scoped-token", "atleast one image must be provided", true},
		{"wrong audience", "wrong-audience", "scoped-token", testCaller, false, "Bearer scoped-token", "Token is not authorized", true},
		{"wrong caller", testAudience, "scoped-token", "system:serviceaccount:default:untrusted", false, "Bearer scoped-token", "Token is not authorized", true},
		{"omitted audience accepts old token", "", "old-token", testCaller, false, "Bearer old-token", "atleast one image must be provided", true},
		{"omitted audience rejects scoped token", "", "scoped-token", testCaller, false, "Bearer scoped-token", "Token is not authorized", true},
		{"explicit audience rejects old token", testAudience, "old-token", testCaller, false, "Bearer old-token", "Token is not authorized", true},
		{"review error denies request", testAudience, "scoped-token", testCaller, true, "Bearer scoped-token", "review unavailable", true},
		{"missing header denies request", testAudience, "", testCaller, false, "", "Authorization header not supplied", false},
	}
	processTest := t
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reviews := make(chan authv1.TokenReview, 1)
			api := newTestAPIServer(processTest, func(w http.ResponseWriter, r *http.Request) {
				review, err := decodeTestTokenReview(r)
				if err != nil {
					t.Errorf("decode TokenReview: %v", err)
					http.Error(w, "bad review", http.StatusBadRequest)
					return
				}
				reviews <- review
				if tt.reviewErr {
					w.WriteHeader(http.StatusInternalServerError)
					writeTestJSON(t, w, metav1.Status{
						TypeMeta: metav1.TypeMeta{APIVersion: "v1", Kind: "Status"},
						Status:   "Failure", Message: "review unavailable", Reason: metav1.StatusReasonInternalError, Code: http.StatusInternalServerError,
					})
					return
				}
				tokenAudience := testAudience
				if review.Spec.Token == "old-token" {
					tokenAudience = "api-server-audience"
				}
				requested := review.Spec.Audiences
				if len(requested) == 0 {
					requested = []string{"api-server-audience"}
				}
				review.Status = authv1.TokenReviewStatus{
					Authenticated: slices.Contains(requested, tokenAudience),
					User:          authv1.UserInfo{Username: tt.username},
				}
				if review.Status.Authenticated {
					review.Status.Audiences = []string{tokenAudience}
				}
				writeTestJSON(t, w, review)
			})
			setTestKubeconfig(t, api.URL)
			config := testVerifierConfig()
			config.tokenAudiences = parseTestAudiences(t, tt.audiences)
			verifier := newImageVerifier(zap.NewNop().Sugar(), config)
			request := httptest.NewRequest(http.MethodPost, "/checkimages", strings.NewReader("{}"))
			request.Header.Set("Authorization", tt.authHeader)
			response := httptest.NewRecorder()
			verifier.HandleCheckImages(response, request)
			wantStatus := http.StatusNotAcceptable
			if !tt.wantReview {
				wantStatus = http.StatusUnauthorized
			}
			if response.Code != wantStatus || strings.TrimSpace(response.Body.String()) != tt.wantBody {
				t.Fatalf("response %d %q, want %d %q", response.Code, response.Body.String(), wantStatus, tt.wantBody)
			}
			if !tt.wantReview {
				select {
				case review := <-reviews:
					t.Fatalf("unexpected TokenReview: %+v", review.Spec)
				default:
				}
				return
			}
			select {
			case review := <-reviews:
				if review.Spec.Token != tt.token || !reflect.DeepEqual(review.Spec.Audiences, []string(config.tokenAudiences)) {
					t.Fatalf("TokenReview spec %+v does not match configured audiences/token", review.Spec)
				}
			default:
				t.Fatal("handler did not create a TokenReview")
			}
			// A validation failure after authentication is not successful signature verification.
		})
	}
	testSignedImageContract(t)
}

func isolateVerifierFiles(t *testing.T) {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("DOCKER_CONFIG", root)
	t.Setenv("XDG_CONFIG_HOME", root)
	t.Setenv("XDG_RUNTIME_DIR", root)
	t.Setenv("REGISTRY_AUTH_FILE", filepath.Join(root, "unused-auth.json"))
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")
	t.Setenv("POD_NAMESPACE", "test")
	if err := os.WriteFile(filepath.Join(root, "config.json"), []byte(`{"auths":{}}`), 0600); err != nil {
		t.Fatal(err)
	}
	notationutils.NotationPath = filepath.Join(root, "policies")
	dir.UserConfigDir = filepath.Join(root, "notation")
	dir.UserLibexecDir = filepath.Join(root, "plugins")
	dir.UserCacheDir = filepath.Join(root, "cache")
	if err := os.MkdirAll(notationutils.NotationPath, 0700); err != nil {
		t.Fatal(err)
	}
}

func testVerifierConfig() verifierConfig {
	return verifierConfig{
		reviewToken:          true,
		maxSignatureAttempts: 30,
		cacheMaxSize:         1000,
		cacheTTL:             time.Hour,
		allowedUsers: []string{
			testCaller,
			"system:serviceaccount:kyverno:kyverno-reports-controller",
		},
		providerKeychain: testKeychain{},
	}
}

type testKeychain struct{}

func (testKeychain) Resolve(authn.Resource) (authn.Authenticator, error) {
	return authn.Anonymous, nil
}

func newTestAPIServer(t *testing.T, review http.HandlerFunc) *httptest.Server {
	t.Helper()
	stop := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/apis/authentication.k8s.io/v1/tokenreviews" && r.Method == http.MethodPost {
			review(w, r)
			return
		}
		if r.URL.Query().Get("watch") == "true" {
			select {
			case <-stop:
			case <-r.Context().Done():
			}
			return
		}
		kind := "SecretList"
		if strings.HasSuffix(r.URL.Path, "/configmaps") {
			kind = "ConfigMapList"
		} else if !strings.HasSuffix(r.URL.Path, "/secrets") {
			http.Error(w, "unexpected API request: "+r.URL.Path, http.StatusNotFound)
			return
		}
		writeTestJSON(t, w, map[string]interface{}{
			"apiVersion": "v1", "kind": kind, "metadata": metav1.ListMeta{ResourceVersion: "1"}, "items": []interface{}{},
		})
	}))
	t.Cleanup(func() {
		close(stop)
		server.Close()
	})
	return server
}

func setTestKubeconfig(t *testing.T, server string) {
	t.Helper()
	config := clientcmdapi.Config{
		Clusters:       map[string]*clientcmdapi.Cluster{"test": {Server: server}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"test": {}},
		Contexts:       map[string]*clientcmdapi.Context{"test": {Cluster: "test", AuthInfo: "test"}},
		CurrentContext: "test",
	}
	data, err := clientcmd.Write(config)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KUBECONFIG", path)
}

func writeTestJSON(t *testing.T, w io.Writer, value interface{}) {
	t.Helper()
	if err := json.NewEncoder(w).Encode(value); err != nil {
		t.Errorf("encode test response: %v", err)
	}
}

func decodeTestTokenReview(r *http.Request) (authv1.TokenReview, error) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		return authv1.TokenReview{}, err
	}
	obj, _, err := clientgoscheme.Codecs.UniversalDeserializer().Decode(data, nil, nil)
	if err != nil {
		return authv1.TokenReview{}, err
	}
	review, ok := obj.(*authv1.TokenReview)
	if !ok {
		return authv1.TokenReview{}, fmt.Errorf("expected TokenReview, got %T", obj)
	}
	return *review, nil
}

func requireTestNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func testPolicyDocument(store, identity string) string {
	return fmt.Sprintf(`{"version":"1.0","trustPolicies":[{"name":"test","registryScopes":["*"],"signatureVerification":{"level":"strict"},"trustStores":["ca:%s"],"trustedIdentities":[%q]}]}`, store, identity)
}
