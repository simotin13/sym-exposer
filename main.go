package main

import (
	"fmt"
	"os"
	coff "sym-exposer/coff"
	elf "sym-exposer/elf"
	"unsafe"
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

	if elf.IsELF64(bin) {

	}

	if coff.IsCoffX64(bin) {
		var offset uint64 = 0
		coffHdr, err := coff.ParseCoffHeader(bin)
		if err != nil {
			panic(err)
		}
		coffHdr.Show()

		size := unsafe.Sizeof(coffHdr)
		offset += uint64(size)
		coff.ParseSections(bin, &coffHdr)
	}

}
