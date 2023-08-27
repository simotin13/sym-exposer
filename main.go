package main

import (
	"fmt"
	"os"
	coff "sym-exposer/coff"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage sym-exporser <target.obj>")
		os.Exit(-1)
	}
	// check target module is exist
	var filePath = os.Args[1]
	fi, err := os.Stat(filePath)
	if err != nil {
		os.Exit(-1)
	}

	f, err := os.Open(filePath)
	if err != nil {
		os.Exit(-1)
	}
	defer f.Close()

	bin := make([]byte, fi.Size())
	f.Read(bin)

	fmt.Println(coff.IsCoffX64(bin))
}
