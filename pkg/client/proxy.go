package client

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"sync"
	"time"

	"github.com/golang/glog"
)

// State describes the state of a service being proxied.
type State struct {
	ID       string
	Endpoint string
	Backend  *url.URL
}

// String returns the string format of state.
func (s State) String() string {
	return s.ID + " " + s.Endpoint + ">" + s.Backend.String()
}

// ReverseProxy exposes endpoints in desired state and serves the backend.
type ReverseProxy struct {
	Dialer *Dialer

	forwardersLock sync.RWMutex
	forwarders     map[string]*forwarder
}

type forwarder struct {
	state   State
	cancel  func()
	stopped sync.WaitGroup
}

// Reconcile reconiles the current forwarders according to the desired states.
func (p *ReverseProxy) Reconcile(ctx context.Context, desiredStates map[string]State) {
	stops, forwarders := make(map[string]*forwarder), make(map[string]*forwarder)
	starts := make(map[string]State)
	p.forwardersLock.RLock()
	for id, fwd := range p.forwarders {
		desired, ok := desiredStates[id]
		if !ok {
			stops[id] = fwd
			continue
		}
		if desired.Endpoint != fwd.state.Endpoint || desired.Backend.String() != fwd.state.Backend.String() {
			stops[id], starts[id] = fwd, desired
			continue
		}
		forwarders[id] = fwd
	}
	for id, state := range desiredStates {
		if p.forwarders[id] == nil {
			starts[id] = state
		}
	}
	p.forwardersLock.RUnlock()

	var wg sync.WaitGroup
	wg.Add(len(stops))
	for _, fwd := range stops {
		glog.Infof("STOPPING %s", fwd.state)
		go func(fwd *forwarder) {
			fwd.cancel()
			fwd.stopped.Wait()
			glog.Infof("STOPPED %s", fwd.state)
			wg.Done()
		}(fwd)
	}
	wg.Wait()

	for id, state := range starts {
		fwdCtx, cancel := context.WithCancel(ctx)
		fwd := &forwarder{state: state, cancel: cancel}
		fwd.stopped.Add(1)
		glog.Infof("START %s", fwd.state)
		forwarders[id] = fwd
		go fwd.run(fwdCtx, p.Dialer)
	}

	p.forwardersLock.Lock()
	p.forwarders = forwarders
	p.forwardersLock.Unlock()
}

func (f *forwarder) run(ctx context.Context, dialer *Dialer) {
	defer f.stopped.Done()
	for {
		err := f.serve(ctx, dialer)
		if err == nil || errors.Is(err, context.Canceled) {
			return
		}
		glog.Errorf("Serve error (%s): %v", f.state, err)
		if !f.backOff(ctx) {
			return
		}
	}
}

func (f *forwarder) serve(ctx context.Context, dialer *Dialer) error {
	client, err := dialer.Dial(ctx)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := client.ListenAndServeHTTP(ctx, f.state.Endpoint, httputil.NewSingleHostReverseProxy(f.state.Backend)); !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func (f *forwarder) backOff(ctx context.Context) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(time.Second):
	}
	return true
}
