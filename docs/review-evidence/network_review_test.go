package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestReviewConcurrentDial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer server.Close()
	p := NetworkPolicy{AllowLoopback: true, Timeout: time.Second, MaxRedirects: 5}
	c, _, err := p.Client(context.Background(), server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 30; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, e := c.Get(server.URL)
			if e == nil {
				r.Body.Close()
			}
		}()
	}
	wg.Wait()
}
