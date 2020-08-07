package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/evo-cloud/epd/pkg/endpoint"
	"github.com/evo-cloud/epd/pkg/ssh"
	"github.com/golang/glog"
)

var (
	listenAddr   = flag.String("addr", ":2022", "Listening address")
	bindAddr     = flag.String("bind-addr", "localhost", "Bind address for remote forwarding ports")
	endpointExec = flag.String("endpoint-exec", "", "Endpoint setup executable")
	hostKeyFiles = flag.String("host-key-files", "", "Comma-separated host key files")
)

func init() {
	flag.StringVar(&ssh.AuthorizedKeysFile, "authorized-keys-file", ssh.AuthorizedKeysFile, "SSH authorized_keys file")
}

func main() {
	flag.Parse()

	if *hostKeyFiles != "" {
		ssh.HostKeyFiles = strings.Split(*hostKeyFiles, ",")
	}

	ctx, cancel := context.WithCancel(context.Background())
	server := ssh.NewServer()
	if err := server.DefaultConfig(); err != nil {
		glog.Exitf("Load config error: %v", err)
	}
	server.BindAddress = *bindAddr

	if *endpointExec != "" {
		configurator := &endpoint.Exec{Program: *endpointExec}
		server.ListenCallback = configurator.ListenCallback(server.BindAddress)
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		<-sigCh
		os.Exit(1)
	}()

	if err := server.ListenAndServe(ctx, *listenAddr); err != nil {
		glog.Exitf("Server start error: %v", err)
	}
}
