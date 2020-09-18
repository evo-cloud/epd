package integration

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ssh"

	client "github.com/evo-cloud/spf/pkg/client"
	spfssh "github.com/evo-cloud/spf/pkg/ssh"
)

var (
	errUnauthorized = errors.New("unauthorized")
)

// TestEnv provides test environments for client and server.
type TestEnv struct {
	ClientConfig ssh.ClientConfig
	ServerConfig ssh.ServerConfig

	signer ssh.Signer
}

// TestServer wraps a server for test.
type TestServer struct {
	Env    *TestEnv
	Ln     net.Listener
	Server *spfssh.Server

	ForwardMapCh chan struct{}

	forwardMapLock sync.Mutex
	ForwardMap     map[spfssh.ForwardAddr]string

	errCh chan error
}

// TestHTTPServer exposes a remote address and serves HTTP requests.
type TestHTTPServer struct {
	Client  *client.Client
	Content string

	cancel func()
	errCh  chan error
}

// TestBackendProvider implements client.StatesProvider for dynamically add/remove backends.
type TestBackendProvider struct {
	notifyChanges func()

	backendsLock sync.RWMutex
	backends     map[string]*backendServer
}

type backendServer struct {
	ln    net.Listener
	errCh chan error
}

func waitForErr(t *testing.T, errCh <-chan error) error {
	t.Helper()
	select {
	case err, ok := <-errCh:
		if ok {
			return err
		}
	case <-time.After(time.Second):
		t.Fatalf("waitForErr timed out")
	}
	return nil
}

// NewTestEnv creates a new TestEnv.
func NewTestEnv(t *testing.T) *TestEnv {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	require.NoError(t, err)
	env := &TestEnv{}
	env.signer, err = ssh.NewSignerFromKey(key)
	require.NoError(t, err)
	env.ServerConfig.SetDefaults()
	env.ServerConfig.AddHostKey(env.signer)
	marshaledPubKey := env.signer.PublicKey().Marshal()
	env.ServerConfig.PublicKeyCallback = func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		marshaled := key.Marshal()
		if bytes.Equal(marshaled, marshaledPubKey) {
			return &ssh.Permissions{}, nil
		}
		return nil, errUnauthorized
	}
	env.ServerConfig.ServerVersion = "SSH-2.0-GATEWAY-1"
	env.ClientConfig.User = "test"
	env.ClientConfig.Auth = []ssh.AuthMethod{ssh.PublicKeys(env.signer)}
	env.ClientConfig.HostKeyCallback = ssh.FixedHostKey(env.signer.PublicKey())
	return env
}

// StartTestServer starts a test server.
func (e *TestEnv) StartTestServer(ctx context.Context, t *testing.T) *TestServer {
	t.Helper()
	ln, err := net.Listen("tcp", "localhost:")
	require.NoError(t, err)
	s := &TestServer{
		Env:          e,
		Ln:           ln,
		Server:       spfssh.NewServer(),
		ForwardMapCh: make(chan struct{}, 1),
		ForwardMap:   make(map[spfssh.ForwardAddr]string),
		errCh:        make(chan error, 1),
	}
	s.Server.Config = e.ServerConfig
	s.Server.Setup = spfssh.ForwardingSetupFunc(func(ctx context.Context, faddr spfssh.ForwardAddr, localAddr string, on bool) error {
		s.forwardMapLock.Lock()
		defer s.forwardMapLock.Unlock()
		if on {
			s.ForwardMap[faddr] = localAddr
		} else {
			delete(s.ForwardMap, faddr)
		}
		select {
		case s.ForwardMapCh <- struct{}{}:
		default:
		}
		return nil
	})

	go func() {
		s.errCh <- s.Server.Serve(ctx, ln)
		close(s.errCh)
	}()
	return s
}

// NewDialer creates a Dialer to connect to this server.
func (s *TestServer) NewDialer() *client.Dialer {
	return &client.Dialer{
		ServerAddr: s.Ln.Addr().String(),
		Config:     &s.Env.ClientConfig,
	}
}

// NewReconciler creates a Reconciler with a ReverseProxy.
func (s *TestServer) NewReconciler() *client.Reconciler {
	return client.NewReconciler(&client.ReverseProxy{
		Dialer: s.NewDialer(),
	})
}

// StartClient connects a client.
func (s *TestServer) StartClient(ctx context.Context, t *testing.T) *client.Client {
	t.Helper()
	client, err := s.NewDialer().Dial(ctx)
	require.NoError(t, err)
	return client
}

// StopAndWait stops the server and waits for it to exit.
func (s *TestServer) StopAndWait(t *testing.T) error {
	t.Helper()
	s.Ln.Close()
	return waitForErr(t, s.errCh)
}

// WaitForwardMapChange waits until change happened in ForwardMap.
func (s *TestServer) WaitForwardMapChange(t *testing.T) {
	t.Helper()
	select {
	case <-s.ForwardMapCh:
	case <-time.After(time.Second):
		t.Fatal("WaitForwardMapChange timed out")
	}
}

// WaitAndTestEndpoint waits until endpoint is exposed and send a simple HTTP GET against the endpoint.
func (s *TestServer) WaitAndTestEndpoint(t *testing.T, endpoint string) string {
	t.Helper()
	s.WaitForwardMapChange(t)
	addr := s.ForwardMap[spfssh.ForwardAddr{SocketPath: endpoint}]
	require.NotEmpty(t, addr)
	resp, err := http.Get("http://" + addr)
	require.NoError(t, err)
	data, err := ioutil.ReadAll(resp.Body)
	require.NoError(t, err)
	return string(data)
}

// NewTestHTTPServer starts a test HTTP server.
func NewTestHTTPServer(ctx context.Context, client *client.Client, endpoint string) *TestHTTPServer {
	s := &TestHTTPServer{
		Client: client,
		errCh:  make(chan error, 1),
	}
	ctx, s.cancel = context.WithCancel(ctx)
	go func() {
		s.errCh <- client.ListenAndServeHTTP(ctx, endpoint, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Add("Content-type", "plain/text")
			w.Write([]byte(s.Content))
		}))
	}()
	return s
}

// StopAndWait stops the HTTP server and waits for it to exit.
func (s *TestHTTPServer) StopAndWait(t *testing.T) error {
	t.Helper()
	s.cancel()
	return waitForErr(t, s.errCh)
}

// NewTestBackendProvider creates a TestBackendProvider.
func NewTestBackendProvider() *TestBackendProvider {
	return &TestBackendProvider{
		backends: make(map[string]*backendServer),
	}
}

// NotifyChanges implements client.StatesProvider.
func (p *TestBackendProvider) NotifyChanges(fn func()) {
	p.notifyChanges = fn
}

// DesiredStates implements client.StatesProvider.
func (p *TestBackendProvider) DesiredStates() map[string]client.State {
	states := make(map[string]client.State)
	p.backendsLock.RLock()
	defer p.backendsLock.RUnlock()
	for endpoint, backend := range p.backends {
		states[endpoint] = client.State{
			ID:       endpoint,
			Endpoint: endpoint,
			Backend: &url.URL{
				Scheme: "http",
				Host:   backend.ln.Addr().String(),
			},
		}
	}
	return states
}

// Add adds a backend server.
func (p *TestBackendProvider) Add(t *testing.T, endpoint, content string) {
	t.Helper()
	ln, err := net.Listen("tcp", "localhost:")
	require.NoError(t, err)
	b := &backendServer{ln: ln, errCh: make(chan error, 1)}
	var server http.Server
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-type", "plain/text")
		w.Write([]byte(content))
	})
	go func() {
		b.errCh <- server.Serve(ln)
	}()
	p.backendsLock.Lock()
	p.backends[endpoint] = b
	p.backendsLock.Unlock()
	p.notifyChanges()
}

// Del removes a backend server.
func (p *TestBackendProvider) Del(t *testing.T, endpoint string) {
	t.Helper()
	p.backendsLock.Lock()
	b := p.backends[endpoint]
	delete(p.backends, endpoint)
	p.backendsLock.Unlock()
	p.notifyChanges()
	b.ln.Close()
	waitForErr(t, b.errCh)
}

// StopAllAndWait removes all backend servers and waits for them to stop.
func (p *TestBackendProvider) StopAllAndWait(t *testing.T) {
	t.Helper()
	p.backendsLock.Lock()
	backends := p.backends
	p.backends = make(map[string]*backendServer)
	p.backendsLock.Unlock()
	p.notifyChanges()
	for _, b := range backends {
		b.ln.Close()
		waitForErr(t, b.errCh)
	}
}
