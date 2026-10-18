//go:build !linux || android

package assemblycapture

import "fmt"

type watcher struct{}

func newWatcher(*meter) (*watcher, error) {
	return nil, fmt.Errorf("assembly capture: complete mutation observation is unavailable on this platform")
}
func (*watcher) close() {}
func (*watcher) addPath(string) error {
	return fmt.Errorf("assembly capture: mutation observation unavailable")
}
func (*watcher) drain() error {
	return fmt.Errorf("assembly capture: mutation observation unavailable")
}
