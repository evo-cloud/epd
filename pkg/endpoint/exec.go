package endpoint

import (
	"context"
	"os"
	"os/exec"
)

// Exec invokes external program for setting up an endpoint.
type Exec struct {
	Program string
}

// SetupForwarder implements ForwardingSetup.
func (x *Exec) SetupForwarder(ctx context.Context, remoteAddr, localAddr string, on bool) error {
	action := "open"
	if !on {
		action = "close"
	}
	cmd := exec.CommandContext(ctx, x.Program, action, remoteAddr, localAddr)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
