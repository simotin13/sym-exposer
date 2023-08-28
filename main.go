package main

import (
	"fmt"
	"os"
	binutil "sym-exposer/binutil"
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
		ehdr := elf.NewElf64Ehdr(bin)
		shdrOffset := ehdr.E_shoff

		shdrs := ehdr.GetSectionHeaders(bin)
		strSh := shdrs[ehdr.E_shstrndx]
		secNameStr := bin[strSh.Sh_offset : strSh.Sh_offset+strSh.Sh_size]
		sectionNameMap := make(map[string]int)
		for i, sh := range shdrs {
			secName := ""
			pos := sh.Sh_name
			for {
				if (secNameStr[pos]) == 0 {
					break
				}
				secName += string(secNameStr[pos])
				pos++
			}
			fmt.Printf("section name: %s, sh_link: %d sh_info: %d\n", secName, sh.Sh_link, sh.Sh_info)
			sectionNameMap[secName] = i
		}

		strShIdx, exist := sectionNameMap[".strtab"]
		if !exist {
			panic("not found .strtab section")
		}
		shStrSec := shdrs[strShIdx]
		endOffset := shStrSec.Sh_offset + shStrSec.Sh_size
		strtbl := bin[shStrSec.Sh_offset:endOffset]
		shIdx, exist := sectionNameMap[".symtab"]

		shdrSize := uint64(unsafe.Sizeof(elf.Elf64_Shdr{}))
		symTabShdrOffset := shdrOffset + uint64(shIdx)*shdrSize
		if !exist {
			panic("not found .strtab section")
		}
		sh := shdrs[shIdx]
		endOffset = sh.Sh_offset + sh.Sh_size
		var offset uint64 = sh.Sh_offset

		var localSymIdx uint32 = 0
		var lastLocalSymIdx uint32 = 0
		for offset < endOffset {
			elf64Sym := elf.Elf64_Sym{}
			elf64Sym.St_name, _ = binutil.FromLeToUInt32(bin[offset:])
			offset += uint64(unsafe.Sizeof(elf.Elf64_Word(0)))

			symName := ""
			strOffset := elf64Sym.St_name
			fmt.Printf("strOffset: %d\n", strOffset)
			for strtbl[strOffset] != 0 {
				symName += string(strtbl[strOffset])
				strOffset++
			}

			elf64Sym.St_info = bin[offset]
			fmt.Printf("symName: [%s]\n", symName)
			bind := (elf64Sym.St_info >> 4)
			if bind == elf.STB_LOCAL {
				localSymIdx++
			}

			// シンボルが関数で可視性がローカルであればグローバルに変更する
			lastLocalSymIdx = localSymIdx
			if elf64Sym.St_info&0x0F == elf.STT_FUNC {
				if bind == elf.STB_LOCAL {
					bin[offset] = (elf.STB_GLOBAL << 4) | elf.STT_FUNC&0x0F
					lastLocalSymIdx = localSymIdx - 1
				}
			}
			offset += uint64(unsafe.Sizeof(uint8(0)))

			elf64Sym.St_other = bin[offset]
			offset += uint64(unsafe.Sizeof(uint8(0)))

			elf64Sym.St_shndx, _ = binutil.FromLeToUInt16(bin[offset:])
			offset += uint64(unsafe.Sizeof(elf.Elf64_Half(0)))

			elf64Sym.St_value, _ = binutil.FromLeToUInt64(bin[offset:])
			offset += uint64(unsafe.Sizeof(elf.Elf64_Addr(0)))

			elf64Sym.St_size, _ = binutil.FromLeToUInt64(bin[offset:])
			offset += uint64(unsafe.Sizeof(elf.Elf64_Xword(0)))
		}

		fmt.Printf("lastLocalSymIdx: %d\n", lastLocalSymIdx)
		var elf64Shdr = elf.Elf64_Shdr{}
		offset = symTabShdrOffset

		elf64Shdr.Sh_name, _ = binutil.FromLeToUInt32(bin[offset:])
		offset += uint64(unsafe.Sizeof(elf.Elf64_Word(0)))

		elf64Shdr.Sh_type, _ = binutil.FromLeToUInt32(bin[offset:])
		offset += uint64(unsafe.Sizeof(elf.Elf64_Word(0)))

		elf64Shdr.Sh_flags, _ = binutil.FromLeToUInt64(bin[offset:])
		offset += uint64(unsafe.Sizeof(elf.Elf64_Xword(0)))

		elf64Shdr.Sh_addr, _ = binutil.FromLeToUInt64(bin[offset:])
		offset += uint64(unsafe.Sizeof(elf.Elf64_Addr(0)))

		elf64Shdr.Sh_offset, _ = binutil.FromLeToUInt64(bin[offset:])
		offset += uint64(unsafe.Sizeof(elf.Elf64_Addr(0)))

		elf64Shdr.Sh_size, _ = binutil.FromLeToUInt64(bin[offset:])
		offset += uint64(unsafe.Sizeof(elf.Elf64_Xword(0)))

		elf64Shdr.Sh_link, _ = binutil.FromLeToUInt32(bin[offset:])
		offset += uint64(unsafe.Sizeof(elf.Elf64_Word(0)))

		// シンボルテーブルのSh_infoを書き換える(最後のローカルシンボルのインデックス+1を指すようにする)
		bytes := binutil.FromUint32ToLeBytes(lastLocalSymIdx)
		fmt.Printf("lastLocalSymIdx: %d\n", lastLocalSymIdx)
		fmt.Printf("bytes: %v\n", bytes)
		bin[offset] = bytes[0]
		bin[offset+1] = bytes[1]
		bin[offset+2] = bytes[2]
		bin[offset+3] = bytes[3]

		err := os.WriteFile("new.o", bin, 0644)
		if err != nil {
			fmt.Println("Error writing to file:", err)
			return
		}
	}
}
