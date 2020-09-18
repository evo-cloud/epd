package client

import (
	"context"

	"golang.org/x/crypto/ssh"
)

// Dialer connects to SSH server.
type Dialer struct {
	ServerAddr string
	Config     *ssh.ClientConfig
}

// Dial connects to SSH server.
func (d *Dialer) Dial(ctx context.Context) (*Client, error) {
	client, err := ssh.Dial("tcp", d.ServerAddr, d.Config)
	if err != nil {
		return nil, err
	}
	return &Client{Client: client}, nil
}
