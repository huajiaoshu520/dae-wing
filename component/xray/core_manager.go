// SPDX-License-Identifier: AGPL-3.0-only
package xray

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"sync"
	"time"

	"github.com/daeuniverse/dae-wing/component/xraycore"
)

var activeDialers = struct {
	sync.Mutex
	items map[*Dialer]struct{}
}{items: make(map[*Dialer]struct{})}

func init() { xraycore.Default.SetHooks(validateCore, restartWorkers) }

func dialerSnapshot() []*Dialer {
	activeDialers.Lock()
	defer activeDialers.Unlock()
	result := make([]*Dialer, 0, len(activeDialers.items))
	for d := range activeDialers.items {
		result = append(result, d)
	}
	return result
}

func validateCore(ctx context.Context, binary string) error {
	for _, d := range dialerSnapshot() {
		config, err := d.node.config(10808, "127.0.0.1:10809", "core-validation")
		if err != nil {
			return errors.New("cannot prepare current XHTTP configuration")
		}
		check, cancel := context.WithTimeout(ctx, 10*time.Second)
		cmd := exec.CommandContext(check, binary, "run", "-test", "-config", "stdin:")
		cmd.Stdin = bytes.NewReader(config)
		err = cmd.Run()
		cancel()
		// Xray's parser can include node credentials in errors. Keep output private.
		if err != nil {
			return errors.New("selected Xray cannot validate current XHTTP configurations; previous core was kept")
		}
	}
	return nil
}

func restartWorkers() {
	for _, d := range dialerSnapshot() {
		d.mu.Lock()
		for key, w := range d.workers {
			w.stop()
			delete(d.workers, key)
		}
		d.mu.Unlock()
	}
}
