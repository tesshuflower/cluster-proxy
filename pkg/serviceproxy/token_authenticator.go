package serviceproxy

import (
	"context"
	"time"

	authenticationv1 "k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/token/cache"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/client-go/kubernetes"
)

// newTokenReviewAuthenticator returns an authenticator.Token that validates
// bearer tokens via the Kubernetes TokenReview API. When cacheTTL > 0, the
// authenticator is wrapped with the k8s.io/apiserver token cache, which
// deduplicates concurrent requests for the same token (singleflight) and
// caches results for cacheTTL. cacheErrs=false avoids caching infrastructure
// failures. A TTL of 0 disables caching entirely.
func newTokenReviewAuthenticator(client kubernetes.Interface, cacheTTL time.Duration) authenticator.Token {
	delegate := &tokenReviewAuthenticator{client: client}
	if cacheTTL <= 0 {
		return delegate
	}
	return cache.New(delegate, false, cacheTTL, cacheTTL)
}

// tokenReviewAuthenticator implements authenticator.Token by calling the
// TokenReview API on the given cluster.
type tokenReviewAuthenticator struct {
	client kubernetes.Interface
}

// AuthenticateToken calls the TokenReview API and returns the result.
func (a *tokenReviewAuthenticator) AuthenticateToken(ctx context.Context, token string) (*authenticator.Response, bool, error) {
	tokenReview, err := a.client.AuthenticationV1().TokenReviews().Create(ctx, &authenticationv1.TokenReview{
		Spec: authenticationv1.TokenReviewSpec{
			Token: token,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return nil, false, err
	}

	if !tokenReview.Status.Authenticated {
		return nil, false, nil
	}

	return &authenticator.Response{
		User: &user.DefaultInfo{
			Name:   tokenReview.Status.User.Username,
			UID:    tokenReview.Status.User.UID,
			Groups: tokenReview.Status.User.Groups,
			Extra:  convertExtra(tokenReview.Status.User.Extra),
		},
	}, true, nil
}

// convertExtra converts authenticationv1.ExtraValue (map[string]ExtraValue)
// to the format expected by user.Info (map[string][]string).
func convertExtra(extra map[string]authenticationv1.ExtraValue) map[string][]string {
	if extra == nil {
		return nil
	}
	result := make(map[string][]string, len(extra))
	for k, v := range extra {
		result[k] = []string(v)
	}
	return result
}
