package endpoint

import (
	"context"
	"os"
	"os/exec"

	"github.com/evo-cloud/spf/pkg/ssh"
)

// Exec invokes external program for setting up an endpoint.
type Exec struct {
	Program string
}

// SetupForwarder implements ForwardingSetup.
func (x *Exec) SetupForwarder(ctx context.Context, faddr ssh.ForwardAddr, localAddr string, on bool) error {
	action, faddrType := "open", "tcp"
	if !on {
		action = "close"
	}
	if faddr.SocketPath != "" {
		faddrType = "sock"
	}
	cmd := exec.CommandContext(ctx, x.Program, action, faddrType, faddr.String(), localAddr)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
