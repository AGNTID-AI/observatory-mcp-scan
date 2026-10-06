package oauthflow

import (
	"context"
	"github.com/agntid/observatory/api/internal/scanner"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"
)

type reviewBarrierVault struct{ ready sync.WaitGroup }

func (v *reviewBarrierVault) Put(context.Context, string, map[string]string) error { return nil }
func (v *reviewBarrierVault) Get(context.Context, string) (map[string]string, error) {
	v.ready.Done()
	v.ready.Wait()
	return map[string]string{"access_token": "fixture-token"}, nil
}
func (v *reviewBarrierVault) Delete(context.Context, string) error { return nil }
func TestReviewConcurrentConsume(t *testing.T) {
	v := &reviewBarrierVault{}
	v.ready.Add(2)
	s, _ := New(scanner.NetworkPolicy{}, v, "http://localhost:3000/callback", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.sessions["fixture"] = &oauthSession{view: SessionView{ID: "fixture", Status: "authorized", TargetURL: "https://example.com", ExpiresAt: time.Now().Add(time.Minute)}}
	var wg sync.WaitGroup
	var mu sync.Mutex
	success := 0
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, _, err := s.Consume(context.Background(), "fixture", "https://example.com", "")
			if err == nil && token != "" {
				mu.Lock()
				success++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if success != 1 {
		t.Fatalf("one-time consume returned token to %d concurrent callers", success)
	}
}
func TestReviewExpiryWithoutPolling(t *testing.T) {
	v := newMemoryVault()
	s, _ := New(scanner.NetworkPolicy{}, v, "http://localhost:3000/callback", slog.New(slog.NewTextHandler(io.Discard, nil)))
	s.sessions["fixture"] = &oauthSession{view: SessionView{ID: "fixture", Status: "authorized", ExpiresAt: time.Now().Add(-time.Minute)}}
	v.Put(context.Background(), vaultID("fixture"), map[string]string{"access_token": "fixture-token"})
	time.Sleep(20 * time.Millisecond)
	values, _ := v.Get(context.Background(), vaultID("fixture"))
	if len(values) > 0 {
		t.Fatal("expired token remains in vault without a Get request")
	}
}
