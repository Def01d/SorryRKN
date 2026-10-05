package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sorryrkn/internal/core"
)

func main() {
	root := os.Args[1]
	c, e := core.CatalogFromDir(root, "Flowseal 1.10.3")
	if e != nil {
		panic(e)
	}
	if e = core.SaveJSON(filepath.Join(root, "profiles.json"), c); e != nil {
		panic(e)
	}
	for _, p := range c.Profiles {
		if _, e = core.ResolveArgs(p, root, filepath.Join(root, "bin")); e != nil {
			panic(e)
		}
	}
	fmt.Println("Profiles:", len(c.Profiles))
}
