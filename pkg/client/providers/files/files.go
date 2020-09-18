package files

import (
	"bufio"
	"context"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/golang/glog"

	"github.com/evo-cloud/spf/pkg/client"
)

// Watcher watches files in directores as desired states.
// A file contains one state per line (except empty lines and commented #).
type Watcher struct {
	Dirs    []string
	Pattern string

	changeNotifier func()
}

// NotifyChanges implements client.StatesProvider.
func (w *Watcher) NotifyChanges(callback func()) {
	w.changeNotifier = callback
}

// DesiredStates implements client.StatesProvider.
func (w *Watcher) DesiredStates() map[string]client.State {
	states := make(map[string]client.State)
	pattern := w.Pattern
	if pattern == "" {
		pattern = "*"
	}
	for _, dir := range w.Dirs {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			glog.Errorf("Files: glob(%q) error: %v", dir, err)
			continue
		}
		for _, fn := range matches {
			info, err := os.Lstat(fn)
			if err != nil || info.IsDir() {
				continue
			}
			if err := readStatesFromFile(fn, states); err != nil {
				glog.Errorf("Files: read(%q) error: %v", fn, err)
				continue
			}
		}
	}
	return states
}

// Run starts watching.
func (w *Watcher) Run(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher error: %w", err)
	}
	defer watcher.Close()
	for _, dir := range w.Dirs {
		if err := watcher.Add(dir); err != nil {
			return fmt.Errorf("watch %q error: %w", dir, err)
		}
	}

	for {
		select {
		case <-watcher.Events:
			if fn := w.changeNotifier; fn != nil {
				fn()
			}
		case err := <-watcher.Errors:
			glog.Errorf("Watcher error: %v", err)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func readStatesFromFile(fn string, states map[string]client.State) error {
	f, err := os.Open(fn)
	if err != nil {
		return err
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	var lineNumber int
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		lineNumber++
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		items := strings.SplitN(line, " ", 3)
		if len(items) != 3 {
			glog.Errorf("Files: %s:%d invalid format, expect ID ENDPOINT BACKEND-URL", fn, lineNumber)
			continue
		}
		backend, err := url.Parse(items[2])
		if err != nil {
			glog.Errorf("Files: %s:%d invalid BACKEND-URL (%q): %v", fn, lineNumber, items[1], err)
			continue
		}
		state := client.State{
			ID:       fn + ":" + items[0],
			Endpoint: items[1],
			Backend:  backend,
		}
		states[state.ID] = state
	}
	return nil
}
