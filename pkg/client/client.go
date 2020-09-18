package client

import (
	"context"
	"fmt"
	"net"
	"net/http"

	"golang.org/x/crypto/ssh"
)

// ConnHandler defines the interface for handling an incoming connection.
type ConnHandler interface {
	// HandleConn starts handling of the connection.
	// It blocks the accept loop, so the implementation should return ASAP.
	HandleConn(context.Context, net.Conn) error
}

// Client is the client exposing a public endpoint and listens for incoming connections.
type Client struct {
	Client *ssh.Client
}

// Close implements io.Closer.
func (c *Client) Close() error {
	return c.Client.Close()
}

// ListenAndServeHTTP exposes a public endpoint and serves HTTP requests.
func (c *Client) ListenAndServeHTTP(ctx context.Context, endpoint string, handler http.Handler) error {
	ln, err := c.Client.ListenUnix(endpoint)
	if err != nil {
		return fmt.Errorf("listen %q error: %w", endpoint, err)
	}
	defer ln.Close()
	var server http.Server
	server.BaseContext = func(net.Listener) context.Context { return ctx }
	server.Handler = handler
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ln)
	}()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-errCh:
		return err
	}
}

// ListenAndServe exposes a public endpoint and accepts incoming connections.
func (c *Client) ListenAndServe(ctx context.Context, endpoint string, handler ConnHandler) error {
	ln, err := c.Client.ListenUnix(endpoint)
	if err != nil {
		return err
	}
	connCh, errCh := make(chan net.Conn), make(chan error, 1)
	defer drainConns(connCh)
	defer ln.Close()

	go acceptLoop(ln, connCh, errCh)

	for {
		select {
		case conn, ok := <-connCh:
			if !ok {
				return nil
			}
			if err := handler.HandleConn(ctx, conn); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func acceptLoop(ln net.Listener, connCh chan<- net.Conn, errCh chan<- error) {
	defer close(connCh)
	for {
		conn, err := ln.Accept()
		if err != nil {
			errCh <- err
			return
		}
		connCh <- conn
	}
}

func drainConns(connCh <-chan net.Conn) {
	for conn := range connCh {
		conn.Close()
	}
}
