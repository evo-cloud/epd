package client

import (
	"context"
	"errors"
	"fmt"

	crt "sigs.k8s.io/controller-runtime"
	ccache "sigs.k8s.io/controller-runtime/pkg/cache"
	cclient "sigs.k8s.io/controller-runtime/pkg/client"
)

var (
	// ErrCacheSync indicates waiting for cache sync failed.
	ErrCacheSync = errors.New("waiting for cache sync failed")
)

// Client is a Kubernetes client with cache.
type Client struct {
	cclient.Client
	Cache ccache.Cache
}

// New creates a Client with default configurations.
func New() (*Client, error) {
	config, err := crt.GetConfig()
	if err != nil {
		return nil, fmt.Errorf("get config error: %w", err)
	}
	client, err := cclient.New(config, cclient.Options{})
	if err != nil {
		return nil, fmt.Errorf("create client error: %w", err)
	}
	cache, err := ccache.New(config, ccache.Options{})
	if err != nil {
		return nil, fmt.Errorf("create cache error: %w", err)
	}
	return &Client{Client: client, Cache: cache}, nil
}

// StartAndWaitForSync starts sync cache in the background and wait for initial sync to complete.
func (c *Client) StartAndWaitForSync(ctx context.Context) error {
	go c.Cache.Start(ctx.Done())
	if !c.Cache.WaitForCacheSync(ctx.Done()) {
		return ErrCacheSync
	}
	return nil
}
