package client

import (
	"context"
	"sync"
)

// StatesProvider defines the abstract desired states provider.
type StatesProvider interface {
	NotifyChanges(func())
	DesiredStates() map[string]State
}

// Reconciler aggregates desired states and reconciles ReverseProxy.
type Reconciler struct {
	Proxy *ReverseProxy

	reconcileCh chan struct{}

	providersLock sync.RWMutex
	providers     map[string]StatesProvider
}

// NewReconciler creates a Reconciler.
func NewReconciler(proxy *ReverseProxy) *Reconciler {
	return &Reconciler{
		Proxy:       proxy,
		reconcileCh: make(chan struct{}, 1),
		providers:   make(map[string]StatesProvider),
	}
}

// AddProvider adds a provider.
func (r *Reconciler) AddProvider(id string, provider StatesProvider) {
	r.providersLock.Lock()
	defer r.providersLock.Unlock()
	r.providers[id] = provider
	provider.NotifyChanges(r.requestReconcile)
}

// Run executes the reconciliation loop.
func (r *Reconciler) Run(ctx context.Context) error {
	r.reconcile(ctx)
	for {
		select {
		case <-r.reconcileCh:
			r.reconcile(ctx)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (r *Reconciler) requestReconcile() {
	select {
	case r.reconcileCh <- struct{}{}:
	default:
	}
}

func (r *Reconciler) reconcile(ctx context.Context) {
	desiredStates := make(map[string]State)
	r.providersLock.RLock()
	for id, provider := range r.providers {
		states := provider.DesiredStates()
		for _, state := range states {
			desiredState := state
			desiredState.ID = id + ":" + state.ID
			desiredStates[desiredState.ID] = desiredState
		}
	}
	r.providersLock.RUnlock()
	r.Proxy.Reconcile(ctx, desiredStates)
}
