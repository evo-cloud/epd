package ssh

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"

	"github.com/golang/glog"
	"golang.org/x/crypto/ssh"
)

const (
	reqTypeTCPIPForward       = "tcpip-forward"
	reqTypeCancelTCPIPForward = "cancel-tcpip-forward"
	chnForwardedTCPIP         = "forwarded-tcpip"
)

var (
	errUnsupported  = errors.New("unsupported")
	errNotFound     = errors.New("not found")
	errUnauthorized = errors.New("unauthorized")
	errAddrInUse    = errors.New("address in-use")

	// ErrNoHostKeys indicates no host keys are found.
	// It's returned by Server.DefaultConfig.
	ErrNoHostKeys = errors.New("no host keys")

	// HostKeyFiles is the default list of host key files
	// to be loaded by Server.DefaultConfig.
	HostKeyFiles = []string{
		"/etc/ssh/ssh_host_rsa_key",
		"/etc/ssh/ssh_host_dsa_key",
		"/etc/ssh/ssh_host_ecdsa_key",
		"/etc/ssh/ssh_host_ed25519_key",
	}

	// AuthorizedKeysFile specifies authorized_keys file.
	AuthorizedKeysFile = "~/.ssh/authorized_keys"
)

// AuthorizedKeysCallback returns the callback for authentication
// using authorized_keys file from home directory.
func AuthorizedKeysCallback() (func(ssh.ConnMetadata, ssh.PublicKey) (*ssh.Permissions, error), error) {
	fn := AuthorizedKeysFile
	if strings.HasPrefix(fn, "~") {
		homeDir := os.Getenv("HOME")
		if homeDir == "" {
			u, err := user.Current()
			if err != nil {
				return nil, fmt.Errorf("get current user error: %w", err)
			}
			homeDir = u.HomeDir
		}
		fn = homeDir + fn[1:]
	}
	var info os.FileInfo
	var keys [][]byte
	return func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		marshaled := key.Marshal()
		var err error
		if info, keys, err = loadAuthorizedKeysIfChanged(fn, info, keys); err != nil {
			glog.Errorf("LoadAuthorizedKeysIfChanged(%q) error: %v", fn, err)
		}
		for _, key := range keys {
			if bytes.Equal(marshaled, key) {
				return &ssh.Permissions{}, nil
			}
		}
		return nil, errUnauthorized
	}, nil
}

func loadAuthorizedKeysIfChanged(fn string, saved os.FileInfo, savedKeys [][]byte) (os.FileInfo, [][]byte, error) {
	info, err := os.Stat(fn)
	if err != nil {
		return saved, savedKeys, err
	}
	if saved != nil && info.Name() == saved.Name() &&
		info.Size() == saved.Size() && info.ModTime() == saved.ModTime() {
		return saved, savedKeys, nil
	}

	keys, err := LoadAuthorizedKeys(fn)
	if err != nil {
		return saved, savedKeys, err
	}
	marshaled := make([][]byte, len(keys))
	for n, key := range keys {
		marshaled[n] = key.Marshal()
	}
	return info, marshaled, nil
}

// LoadAuthorizedKeys loads authorized_keys file.
func LoadAuthorizedKeys(fn string) ([]ssh.PublicKey, error) {
	data, err := ioutil.ReadFile(fn)
	if err != nil {
		return nil, fmt.Errorf("read %q error: %w", fn, err)
	}
	var keys []ssh.PublicKey
	for len(data) > 0 {
		var key ssh.PublicKey
		key, _, _, data, err = ssh.ParseAuthorizedKey(data)
		if err != nil {
			return keys, fmt.Errorf("parse %q error: %w", fn, err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// ForwardingSetup is optional extension to perform extra work for setting up forwarding.
type ForwardingSetup interface {
	SetupForwarder(ctx context.Context, remoteAddr, localAddr string, on bool) error
}

// ForwardingSetupFunc is func form of ForwardingSetup.
type ForwardingSetupFunc func(ctx context.Context, remoteAddr, localAddr string, on bool) error

// SetupForwarder implements ForwardingSetup.
func (f ForwardingSetupFunc) SetupForwarder(ctx context.Context, remoteAddr, localAddr string, on bool) error {
	return f(ctx, remoteAddr, localAddr, on)
}

// Server implements the gateway using SSH.
type Server struct {
	Config      ssh.ServerConfig
	BindAddress string
	Setup       ForwardingSetup
}

// NewServer creates Server.
func NewServer() *Server {
	s := &Server{}
	s.Config.SetDefaults()
	s.Config.ServerVersion = "SSH-2.0-GATEWAY-1"
	s.BindAddress = "localhost"
	return s
}

// DefaultConfig loads default config.
func (s *Server) DefaultConfig() error {
	keyCount := 0
	for _, fn := range HostKeyFiles {
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			glog.Warningf("Skip host key %q, read error: %v", fn, err)
			continue
		}
		signer, err := ssh.ParsePrivateKey(data)
		if err != nil {
			glog.Warningf("Skip host key %q, parse error: %v", fn, err)
			continue
		}
		s.Config.AddHostKey(signer)
		keyCount++
		glog.Infof("Loaded host key %q", fn)
	}
	if keyCount == 0 {
		return ErrNoHostKeys
	}

	authKeyCallback, err := AuthorizedKeysCallback()
	if err != nil {
		return err
	}
	s.Config.PublicKeyCallback = authKeyCallback
	return nil
}

// ListenAndServe listens on specified address and start serving clients.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer ln.Close()
	go closeWhenDone(ctx, ln)
	glog.Infof("Server listening at %s", ln.Addr())
	return s.Serve(ctx, ln)
}

// Serve starts serving clients.
func (s *Server) Serve(ctx context.Context, ln net.Listener) error {
	for {
		conn, err := ln.Accept()
		if err != nil {
			if isClosedErr(err) {
				return nil
			}
			return err
		}
		go s.serveConn(ctx, conn)
	}
}

func (s *Server) serveConn(ctx context.Context, conn net.Conn) {
	glog.V(2).Infof("Incoming Conn from %s", conn.RemoteAddr())
	sshConn, chnsCh, reqsCh, err := ssh.NewServerConn(conn, &s.Config)
	if err != nil {
		glog.V(2).Infof("Rejected Conn from %s: %v", conn.RemoteAddr(), err)
		return
	}

	serverConn := &connection{
		server:    s,
		conn:      sshConn,
		chnsCh:    chnsCh,
		reqsCh:    reqsCh,
		logPrefix: fmt.Sprintf("SSH[%s@%s] ", sshConn.User(), sshConn.RemoteAddr()),
	}

	serverConn.log("ACCEPTED")
	defer serverConn.log("CLOSED")

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer conn.Close()

	serverConn.run(ctx)
}

func (s *Server) setupForwarder(ctx context.Context, remoteAddr, localAddr string, on bool) error {
	if setup := s.Setup; setup != nil {
		return setup.SetupForwarder(ctx, remoteAddr, localAddr, on)
	}
	return nil
}

type forwardAddr struct {
	BindAddr string
	BindPort uint32
}

func (a forwardAddr) String() string {
	return a.BindAddr + ":" + strconv.FormatUint(uint64(a.BindPort), 10)
}

type connection struct {
	server *Server
	conn   *ssh.ServerConn
	chnsCh <-chan ssh.NewChannel
	reqsCh <-chan *ssh.Request

	logPrefix string

	listenersLock sync.Mutex
	listeners     map[forwardAddr]net.Listener
}

func (c *connection) log(format string, args ...interface{}) {
	if glog.V(1) {
		glog.InfoDepth(1, c.logPrefix+fmt.Sprintf(format, args...))
	}
}

func (c *connection) localAddr(ln net.Listener) string {
	return c.server.BindAddress + ":" + strconv.FormatUint(uint64(ln.Addr().(*net.TCPAddr).Port), 10)
}

func (c *connection) cleanup() {
	c.listenersLock.Lock()
	listeners := c.listeners
	c.listeners = nil
	c.listenersLock.Unlock()
	for _, ln := range listeners {
		ln.Close()
	}
	// Drain request chan.
	for range c.reqsCh {
	}
}

func (c *connection) run(ctx context.Context) {
	defer c.cleanup()
	go rejectChannels(c.chnsCh)
	for {
		select {
		case <-ctx.Done():
			return
		case req, ok := <-c.reqsCh:
			if !ok {
				return
			}
			var data []byte
			var err error
			switch req.Type {
			case reqTypeTCPIPForward:
				data, err = c.forwardStart(ctx, req)
			case reqTypeCancelTCPIPForward:
				data, err = c.forwardCancel(ctx, req)
			default:
				err = errUnsupported
			}
			if err != nil {
				c.log("REQ %s error: %v", req.Type, err)
				req.Reply(false, []byte(err.Error()))
			} else {
				req.Reply(true, data)
			}
		}
	}
}

func (c *connection) forwardStart(ctx context.Context, req *ssh.Request) ([]byte, error) {
	var faddr forwardAddr
	if err := ssh.Unmarshal(req.Payload, &faddr); err != nil {
		return nil, err
	}

	ln, err := net.Listen("tcp4", c.server.BindAddress+":0")
	if err != nil {
		return nil, err
	}

	if !c.addListener(faddr, ln) {
		ln.Close()
		return nil, errAddrInUse
	}

	c.log("REQ %s %s bind-to %s", req.Type, faddr, ln.Addr())
	if err := c.server.setupForwarder(ctx, faddr.String(), c.localAddr(ln), true); err != nil {
		ln.Close()
		c.removeListener(faddr, ln)
		return nil, fmt.Errorf("setup error: %w", err)
	}

	go c.forwardRun(ctx, faddr, ln)

	return ssh.Marshal(&struct {
		BindPort uint32
	}{BindPort: faddr.BindPort}), nil
}

func (c *connection) forwardRun(ctx context.Context, faddr forwardAddr, ln net.Listener) {
	logPrefix := fmt.Sprintf("FWD-CLOSE %s bind-to %s ", faddr, ln.Addr())
	localAddr := c.localAddr(ln)
	go closeWhenDone(ctx, ln)
	defer func() {
		c.removeListener(faddr, ln)
		// Use a different context as the current one may be already canceled.
		if err := c.server.setupForwarder(context.Background(), faddr.String(), localAddr, false); err != nil {
			c.log("%s teardown error: %v", logPrefix, err)
		}
		c.log("%s", logPrefix)
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go c.forwardConn(ctx, conn, faddr)
	}
}

func (c *connection) forwardConn(ctx context.Context, conn net.Conn, faddr forwardAddr) {
	defer conn.Close()
	originAddr := conn.RemoteAddr().(*net.TCPAddr)
	chn, reqsCh, err := c.conn.OpenChannel(chnForwardedTCPIP, ssh.Marshal(&struct {
		DestAddr   string
		DestPort   uint32
		OriginAddr string
		OriginPort uint32
	}{
		DestAddr:   faddr.BindAddr,
		DestPort:   faddr.BindPort,
		OriginAddr: originAddr.IP.String(),
		OriginPort: uint32(originAddr.Port),
	}))
	if err != nil {
		c.log("FWD %s from %s error: %v", faddr, conn.RemoteAddr(), err)
		return
	}
	c.log("FWD %s from %s START", faddr, conn.RemoteAddr())
	defer c.log("FWD %s from %s END", faddr, conn.RemoteAddr())
	go ssh.DiscardRequests(reqsCh)
	forward(ctx, chn, conn)
}

func (c *connection) forwardCancel(ctx context.Context, req *ssh.Request) ([]byte, error) {
	var faddr forwardAddr
	if err := ssh.Unmarshal(req.Payload, &faddr); err != nil {
		return nil, err
	}
	c.log("REQ %s %s", req.Type, faddr)
	if ln := c.removeListener(faddr, nil); ln != nil {
		ln.Close()
		return nil, nil
	}
	return nil, errNotFound
}

func (c *connection) addListener(faddr forwardAddr, ln net.Listener) bool {
	c.listenersLock.Lock()
	defer c.listenersLock.Unlock()
	if c.listeners == nil {
		c.listeners = make(map[forwardAddr]net.Listener)
	}
	if _, ok := c.listeners[faddr]; ok {
		return false
	}
	c.listeners[faddr] = ln
	return true
}

func (c *connection) removeListener(faddr forwardAddr, ln net.Listener) net.Listener {
	c.listenersLock.Lock()
	defer c.listenersLock.Unlock()
	existing, ok := c.listeners[faddr]
	if ok && (ln == nil || ln == existing) {
		delete(c.listeners, faddr)
		return existing
	}
	return nil
}

func forward(ctx context.Context, p1, p2 io.ReadWriteCloser) {
	defer p1.Close()
	defer p2.Close()

	var wg sync.WaitGroup
	wg.Add(2)

	ctx, cancel := context.WithCancel(ctx)
	go forwardOneWay(p1, p2, &wg)
	go forwardOneWay(p2, p1, &wg)
	go func() {
		wg.Wait()
		cancel()
	}()
	<-ctx.Done()
}

func forwardOneWay(from io.ReadCloser, to io.WriteCloser, wg *sync.WaitGroup) {
	defer from.Close()
	defer to.Close()
	defer wg.Done()
	io.Copy(to, from)
}

func rejectChannels(chnsCh <-chan ssh.NewChannel) {
	for newChn := range chnsCh {
		newChn.Reject(ssh.UnknownChannelType, "unsupported")
	}
}

// isClosedErr checks an err if caused by listener/connection closed.
func isClosedErr(err error) bool {
	if err == nil {
		return false
	}
	_, ok := err.(*net.OpError)
	return ok && strings.Contains(err.Error(), "use of closed network connection")
}

func closeWhenDone(ctx context.Context, closer io.Closer) {
	if closer != nil {
		<-ctx.Done()
		closer.Close()
	}
}
