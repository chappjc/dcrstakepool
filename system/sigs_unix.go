// +build darwin dragonfly freebsd linux nacl netbsd openbsd solaris

package system

import (
	"os"
	"syscall"
)

func ReloadTemplatesSig(app *Application) {
	reloadTemplatesSig(syscall.SIGUSR1, app)
}
