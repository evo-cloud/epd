package main

import (
	"context"
	"flag"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/golang/glog"

	"github.com/evo-cloud/spf/pkg/client"
	"github.com/evo-cloud/spf/pkg/client/providers/files"
	k8sclient "github.com/evo-cloud/spf/pkg/client/providers/k8s/client"
	"github.com/evo-cloud/spf/pkg/client/providers/k8s/controller"
)

var (
	serverAddr = flag.String("s", os.Getenv("SPF_SERVER"), "Server address")
	keyFile    = flag.String("i", os.Getenv("SPF_KEY_FILE"), "SSH private key file")
	hostsFile  = flag.String("k", os.Getenv("SPF_HOSTS_FILE"), "Known hosts file")
	userName   = flag.String("u", os.Getenv("SPF_USER"), "Override username")

	providerK8s       = flag.Bool("k8s", false, "Enable Kubernetes state provider")
	providerFilesDirs = flag.String("files-dirs", "", "Semi-colon-separated directories to watch for state files")
	providerFilesGlob = flag.String("files-glob", "", "Pattern to filter state files")
)

func main() {
	flag.Parse()

	if *serverAddr == "" {
		glog.Exitf("Missing server address, please specify using -s")
	}
	ctx, cancel := context.WithCancel(context.Background())
	var loader client.ConfigLoader
	if *userName != "" {
		loader.UserName = *userName
	}
	if *keyFile != "" {
		loader.PrivateKeyFile = *keyFile
	}
	if *hostsFile != "" {
		loader.KnownHostsFile = *hostsFile
	}
	config, err := loader.Load()
	if err != nil {
		glog.Exitf("Load SSH client config error: %v", err)
	}
	reconciler := client.NewReconciler(&client.ReverseProxy{
		Dialer: &client.Dialer{ServerAddr: *serverAddr, Config: config},
	})

	var starters []func(context.Context)

	if *providerK8s {
		k8sc, err := k8sclient.New()
		if err != nil {
			glog.Exitf("Create Kubernetes client error: %v", err)
		}
		ctrl, err := controller.New(ctx, k8sc)
		if err != nil {
			glog.Exitf("Create controller error: %v", err)
		}
		reconciler.AddProvider("k8s", ctrl)
		starters = append(starters, func(ctx context.Context) {
			if err := k8sc.StartAndWaitForSync(ctx); err != nil {
				glog.Exitf("Kubernetes: sync cache error: %v", err)
			}
		})
	}

	if *providerFilesDirs != "" {
		dirs := strings.Split(*providerFilesDirs, ":")
		if len(dirs) > 0 {
			w := &files.Watcher{
				Dirs:    dirs,
				Pattern: *providerFilesGlob,
			}
			reconciler.AddProvider("files", w)
			starters = append(starters, func(ctx context.Context) {
				go w.Run(ctx)
			})
		}
	}

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		cancel()
		<-sigCh
		os.Exit(1)
	}()

	for _, fn := range starters {
		fn(ctx)
	}

	reconciler.Run(ctx)
}
