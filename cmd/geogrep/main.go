package main

import (
	"os"

	"geogrep/internal/geogrep"
)

func main() {
	os.Exit(geogrep.Execute(os.Args[1:]))
}
