package endpoint

import (
	"context"
	"fmt"
	"os"
	"os/exec"

	"github.com/evo-cloud/epd/pkg/ssh"
)

// Exec invokes external program for setting up an endpoint.
type Exec struct {
	Program string
}

// ListenCallback returns a ssh.ListenCallback to invoke the external program.
func (x *Exec) ListenCallback(bindAddr string) ssh.ListenCallbackFunc {
	return func(ctx context.Context, host string, port int, on bool) error {
		action := "open"
		if !on {
			action = "close"
		}
		backend := bindAddr + fmt.Sprintf(":%d", port)
		return x.invoke(ctx, action, host, backend)
	}
}

func (x *Exec) invoke(ctx context.Context, action, name, addr string) error {
	cmd := exec.CommandContext(ctx, x.Program, action, name, addr)
	cmd.Env = os.Environ()
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}
