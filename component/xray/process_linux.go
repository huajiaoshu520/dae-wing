// SPDX-License-Identifier: AGPL-3.0-only
package xray

import (
	"os/exec"
	"syscall"
)

func setProcessAttributes(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL}
}
