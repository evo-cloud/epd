package integration

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	spfssh "github.com/evo-cloud/spf/pkg/ssh"
)

func TestSimpleHTTPServer(t *testing.T) {
	ctx := context.Background()
	env := NewTestEnv(t)
	s := env.StartTestServer(ctx, t)
	defer s.StopAndWait(t)
	c := s.StartClient(ctx, t)
	httpSrv := NewTestHTTPServer(ctx, c, "http/test")
	defer httpSrv.StopAndWait(t)
	httpSrv.Content = "test"
	assert.Equal(t, "test", s.WaitAndTestEndpoint(t, "http/test"))
}

func TestReconciler(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	env := NewTestEnv(t)
	s := env.StartTestServer(ctx, t)
	defer s.StopAndWait(t)
	reconciler := s.NewReconciler()
	provider := NewTestBackendProvider()
	defer provider.StopAllAndWait(t)
	reconciler.AddProvider("t", provider)
	errCh := make(chan error, 1)
	defer func() {
		cancel()
		waitForErr(t, errCh)
	}()
	go func() {
		errCh <- reconciler.Run(ctx)
	}()

	provider.Add(t, "http/test1", "test1")
	assert.Equal(t, "test1", s.WaitAndTestEndpoint(t, "http/test1"))
	provider.Add(t, "http/test2", "test2")
	assert.Equal(t, "test2", s.WaitAndTestEndpoint(t, "http/test2"))

	provider.Del(t, "http/test1")
	s.WaitForwardMapChange(t)
	assert.NotContains(t, s.ForwardMap, spfssh.ForwardAddr{SocketPath: "http/test1"})
}
