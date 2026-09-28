//go:build !linux

// SPDX-License-Identifier: AGPL-3.0-only
package xray

import "os/exec"

func setProcessAttributes(cmd *exec.Cmd) {}
