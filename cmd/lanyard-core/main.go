// Command lanyard-core is the headless LANyard core: all networking plus the
// local control API. The GUI starts the same code with --core; a future
// Minecraft mod can start this binary or reuse a core that is already running.
package main

import (
	"os"

	"github.com/jinomee/mc/internal/corecmd"
)

func main() {
	os.Exit(corecmd.Main(os.Args[1:], os.Stdout, os.Stderr))
}
