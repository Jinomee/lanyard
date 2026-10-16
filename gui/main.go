// Command LANyard is the desktop app. It is a thin Wails client of the core:
// started with --core it *is* the core (no window); otherwise it finds or
// starts a core and shows the GUI.
package main

import (
	"embed"
	"os"
	"slices"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"

	"github.com/jinomee/lanyard/internal/brand"
	"github.com/jinomee/lanyard/internal/corecmd"
)

//go:embed all:frontend/dist
var assets embed.FS

// coreFlag starts the background core instead of the window.
const coreFlag = "--core"

func main() {
	if slices.Contains(os.Args[1:], coreFlag) {
		args := []string{"serve", "-idle", "60s"}
		if isInstalled() {
			args = append(args, "-installed")
		}
		os.Exit(corecmd.Main(args, os.Stdout, os.Stderr))
	}

	app := NewApp(os.Args[1:])
	err := wails.Run(&options.App{
		Title:            brand.Name(),
		Width:            980,
		Height:           720,
		MinWidth:         760,
		MinHeight:        560,
		BackgroundColour: &options.RGBA{R: 246, G: 247, B: 249, A: 1},
		AssetServer:      &assetserver.Options{Assets: assets},
		OnStartup:        app.startup,
		OnBeforeClose:    app.beforeClose,
		OnShutdown:       app.shutdown,
		SingleInstanceLock: &options.SingleInstanceLock{
			UniqueId:               brand.ID() + "-gui-7f3c2a",
			OnSecondInstanceLaunch: app.secondInstance,
		},
		Bind: []any{app},
		Windows: &windows.Options{
			Theme: windows.SystemDefault,
		},
	})
	if err != nil {
		println("Error:", err.Error())
		os.Exit(1)
	}
}
