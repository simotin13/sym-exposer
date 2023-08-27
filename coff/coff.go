package coff

import (
	"fmt"
	binutil "sym-exposer/binutil"
	"time"
	"unsafe"
)

type COFFHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type SectionHeader struct {
	Name                 string
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

func IsCoffX64(bin []byte) bool {
	return (bin[0] == 0x64 && bin[1] == 0x86)
}

func ParseCoffHeader(bin []byte) (COFFHeader, error) {
	offset := 0
	var coffHdr = COFFHeader{}
	var err error = nil
	coffHdr.Machine, err = binutil.FromLeToUInt16(bin[offset:])
	if err != nil {
		return coffHdr, err
	}

	offset += 2
	coffHdr.NumberOfSections, _ = binutil.FromLeToUInt16(bin[offset:])
	if err != nil {
		return coffHdr, err
	}

	offset += 2
	coffHdr.TimeDateStamp, _ = binutil.FromLeToUInt32(bin[offset:])
	if err != nil {
		return coffHdr, err
	}

	offset += 4
	coffHdr.PointerToSymbolTable, _ = binutil.FromLeToUInt32(bin[offset:])
	if err != nil {
		return coffHdr, err
	}

	offset += 4
	coffHdr.NumberOfSymbols, _ = binutil.FromLeToUInt32(bin[offset:])
	if err != nil {
		return coffHdr, err
	}

	offset += 2
	coffHdr.SizeOfOptionalHeader, _ = binutil.FromLeToUInt16(bin[offset:])
	if err != nil {
		return coffHdr, err
	}

	offset += 2
	coffHdr.Characteristics, _ = binutil.FromLeToUInt16(bin[offset:])
	if err != nil {
		return coffHdr, err
	}
	return coffHdr, err
}

func ParseSections(bin []byte, coffHdr *COFFHeader) []SectionHeader {
	secHdrs := []SectionHeader{}
	offset := unsafe.Sizeof(COFFHeader{})
	for i := 0; i < int(coffHdr.NumberOfSections); i++ {
		secHdr := parseSection(bin[offset:])
		offset += unsafe.Sizeof(secHdr)
		secHdr.Show()
		secHdrs = append(secHdrs, secHdr)
	}
	return secHdrs
}

func parseSection(bin []byte) SectionHeader {
	var secHdr SectionHeader
	var offset uint64 = 0
	/*
		Name                 [8]byte
		VirtualSize          uint32
		VirtualAddress       uint32
		SizeOfRawData        uint32
		PointerToRawData     uint32
		PointerToRelocations uint32
		PointerToLineNumbers uint32
		NumberOfRelocations  uint16
		NumberOfLineNumbers  uint16
		Characteristics      uint32
	*/
	secHdr.Name = binutil.GetCoffString(bin, offset)
	return secHdr
}

func (coffHdr *COFFHeader) Show() {
	fmt.Printf("Machine:%x\n", coffHdr.Machine)
	fmt.Printf("NumberOfSections:%d\n", coffHdr.NumberOfSections)
	dt := time.Unix(int64(coffHdr.TimeDateStamp), 0)
	fmt.Printf("TimeDateStamp:")
	fmt.Println(dt)
	fmt.Printf("PointerToSymbolTable:0x%x\n", coffHdr.PointerToSymbolTable)
	fmt.Printf("NumberOfSymbols:%d\n", coffHdr.NumberOfSymbols)
	fmt.Printf("SizeOfOptionalHeader:%d\n", coffHdr.SizeOfOptionalHeader)
	fmt.Printf("Characteristics:0x%x\n", coffHdr.Characteristics)
}

func (secHdr *SectionHeader) Show() {
	fmt.Printf("Name:%s\n", secHdr.Name)
	fmt.Printf("VirtualSize:%d\n", secHdr.VirtualSize)
	fmt.Printf("VirtualAddress:0x%x\n", secHdr.VirtualAddress)
	fmt.Printf("SizeOfRawData:%d\n", secHdr.SizeOfRawData)
	fmt.Printf("PointerToRawData:0x%x\n", secHdr.PointerToRawData)
	fmt.Printf("PointerToRelocations:0x%x\n", secHdr.PointerToRelocations)
	fmt.Printf("PointerToLineNumbers:0x%x\n", secHdr.PointerToLineNumbers)
	fmt.Printf("NumberOfRelocations:%d\n", secHdr.NumberOfRelocations)
	fmt.Printf("NumberOfLineNumbers:%d\n", secHdr.NumberOfLineNumbers)
	fmt.Printf("Characteristics:%d\n", secHdr.Characteristics)
}
