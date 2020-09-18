package controller

import (
	"context"
	"fmt"
	"net/url"
	"sync"

	corev1 "k8s.io/api/core/v1"
	k8scache "k8s.io/client-go/tools/cache"

	"github.com/evo-cloud/spf/pkg/client"
	k8sclient "github.com/evo-cloud/spf/pkg/client/providers/k8s/client"
)

const (
	// AnnotationKey specifies the expected annotation in the service.
	AnnotationKey = "spf.evo-cloud/endpoint"
)

// Controller is a controller which watches the Service resources
// and exposes public endpoints for them.
type Controller struct {
	changeNotifier func()

	servicesLock sync.RWMutex
	services     map[string]client.State
}

// New creates a Controller.
func New(ctx context.Context, k8sc *k8sclient.Client) (*Controller, error) {
	informer, err := k8sc.Cache.GetInformer(ctx, &corev1.Service{})
	if err != nil {
		return nil, fmt.Errorf("get informer for v1.Service error: %w", err)
	}
	c := &Controller{
		services: make(map[string]client.State),
	}
	informer.AddEventHandler(&k8scache.ResourceEventHandlerFuncs{
		AddFunc:    func(o interface{}) { c.updateService(o.(*corev1.Service)) },
		UpdateFunc: func(o, n interface{}) { c.updateService(n.(*corev1.Service)) },
		DeleteFunc: func(o interface{}) { c.removeService(o.(*corev1.Service)) },
	})

	return c, nil
}

// NotifyChanges implements StatesProvider.
func (c *Controller) NotifyChanges(callback func()) {
	c.changeNotifier = callback
}

// DesiredStates implements StatesProvider.
func (c *Controller) DesiredStates() map[string]client.State {
	states := make(map[string]client.State)
	c.servicesLock.RLock()
	defer c.servicesLock.RUnlock()
	for id, state := range c.services {
		states[id] = state
	}
	return states
}

func (c *Controller) updateService(o *corev1.Service) {
	state := desiredState(o)
	c.servicesLock.Lock()
	defer c.servicesLock.Unlock()
	_, ok := c.services[state.ID]
	if !ok && state.Endpoint == "" {
		return
	}
	if state.Endpoint == "" {
		delete(c.services, state.ID)
	} else {
		c.services[state.ID] = state
	}
	c.requestReconcile()
}

func (c *Controller) removeService(o *corev1.Service) {
	id := serviceID(o)
	c.servicesLock.Lock()
	defer c.servicesLock.Unlock()
	if _, ok := c.services[id]; ok {
		delete(c.services, id)
		c.requestReconcile()
	}
}

func (c *Controller) requestReconcile() {
	if callback := c.changeNotifier; callback != nil {
		callback()
	}
}

func serviceID(o *corev1.Service) string {
	return o.GetNamespace() + "/" + o.GetName()
}

func desiredState(o *corev1.Service) client.State {
	s := client.State{
		ID:       serviceID(o),
		Endpoint: o.GetAnnotations()[AnnotationKey],
		Backend: &url.URL{
			Scheme: "http",
			Host:   o.GetName() + "." + o.GetNamespace(),
		},
	}
	for _, port := range o.Spec.Ports {
		s.Backend.Host += fmt.Sprintf(":%d", port.Port)
		break
	}
	return s
}
