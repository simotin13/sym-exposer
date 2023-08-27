package coff

type COFFHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

func IsCoffX64(bin []byte) bool {
	return (bin[0] == 0x64 && bin[1] == 0x86)
}
