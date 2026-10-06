package scanner

import (
	"context"
	"testing"
	"time"
)

func TestNetworkPolicyBlocksUnsafeTargets(t *testing.T) {
	p := NetworkPolicy{MaxRedirects: 5, Timeout: time.Second}
	for _, target := range []string{"file:///etc/passwd", "http://169.254.169.254/latest", "http://127.0.0.1:8080"} {
		if _, _, err := p.ValidateURL(context.Background(), target); err == nil {
			t.Errorf("expected %s to be blocked", target)
		}
	}
}

func TestAllowedHeader(t *testing.T) {
	if AllowedHeader("Host") || AllowedHeader("Cookie") || AllowedHeader("X-Forwarded-For") {
		t.Fatal("unsafe header allowed")
	}
	if !AllowedHeader("X-Tenant-ID") {
		t.Fatal("safe custom header blocked")
	}
}
