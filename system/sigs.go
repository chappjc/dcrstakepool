package system

import (
	"fmt"
	"os"
	"os/signal"
)

func reloadTemplatesSig(sig os.Signal, app *Application) {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, sig)

	go func() {
		for {
			sigr := <-sigChan
			fmt.Fprintf(os.Stdout, "Received: %s\n", sig)
			if sigr == sig {
				app.LoadTemplates()
				fmt.Fprintf(os.Stdout, "LoadTemplates() executed.\n")
			}
		}
	}()
}
