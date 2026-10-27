package main

import (
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/google/go-containerregistry/pkg/authn"
	knvVerifier "github.com/nirmata/kyverno-notation-verifier/verifier"
	"go.uber.org/zap"
)

type tokenAudienceList []string

func (a *tokenAudienceList) String() string {
	return strings.Join(*a, ",")
}

func (a *tokenAudienceList) Set(value string) error {
	if value == "" {
		*a = nil
		return nil
	}
	audiences := strings.Split(value, ",")
	for _, audience := range audiences {
		if audience == "" || strings.IndexFunc(audience, unicode.IsSpace) >= 0 {
			return fmt.Errorf("tokenAudiences must contain nonempty, comma-separated audiences without whitespace")
		}
	}
	*a = audiences
	return nil
}

type verifierConfig struct {
	imagePullSecrets      string
	allowInsecureRegistry bool
	pluginConfigMap       string
	maxSignatureAttempts  int
	debug                 bool
	reviewToken           bool
	cacheEnabled          bool
	cacheMaxSize          int64
	cacheTTL              time.Duration
	allowedUsers          []string
	tokenAudiences        tokenAudienceList
	providerKeychain      authn.Keychain
}

func newImageVerifier(logger *zap.SugaredLogger, config verifierConfig) knvVerifier.Verifier {
	return knvVerifier.NewVerifier(logger,
		knvVerifier.WithImagePullSecrets(config.imagePullSecrets),
		knvVerifier.WithInsecureRegistry(config.allowInsecureRegistry),
		knvVerifier.WithPluginConfig(config.pluginConfigMap),
		knvVerifier.WithMaxSignatureAttempts(config.maxSignatureAttempts),
		knvVerifier.WithEnableDebug(config.debug),
		knvVerifier.WithProviderKeychain(config.providerKeychain),
		knvVerifier.WithTokenReviewEnabled(config.reviewToken),
		knvVerifier.WithTokenAudiences(config.tokenAudiences),
		knvVerifier.WithCacheEnabled(config.cacheEnabled),
		knvVerifier.WithMaxCacheSize(config.cacheMaxSize),
		knvVerifier.WithMaxCacheTTL(config.cacheTTL),
		knvVerifier.WithAllowedUsers(config.allowedUsers))
}
