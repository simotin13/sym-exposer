package bintutil

import (
	"bytes"
	"encoding/binary"
	"errors"
)

func FromLeToUInt16(buf []byte) (uint16, error) {
	var val uint16
	if len(buf) < 2 {
		return val, errors.New("buf is too short")
	}

	err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &val)
	if err != nil {
		return val, err
	}
	return val, nil
}

func FromLeToInt16(buf []byte) (int16, error) {
	var val int16
	if len(buf) < 2 {
		return val, errors.New("buf is too short")
	}

	err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &val)
	if err != nil {
		return val, err
	}
	return val, nil
}

func FromLeToUInt32(buf []byte) (uint32, error) {
	var val uint32
	if len(buf) < 4 {
		return val, errors.New("buf is too short")
	}

	err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &val)
	if err != nil {
		return val, err
	}
	return val, nil
}
func FromLeToInt32(buf []byte) (int32, error) {
	var val int32
	if len(buf) < 4 {
		return val, errors.New("buf is too short")
	}

	err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &val)
	if err != nil {
		return val, err
	}
	return val, nil
}

func FromLeToUInt64(buf []byte) (uint64, error) {
	var val uint64
	if len(buf) < 8 {
		return val, errors.New("buf is too short")
	}

	err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &val)
	if err != nil {
		return val, err
	}
	return val, nil
}

func FromLeToInt64(buf []byte) (int64, error) {
	var val int64
	if len(buf) < 8 {
		return val, errors.New("buf is too short")
	}

	err := binary.Read(bytes.NewReader(buf), binary.LittleEndian, &val)
	if err != nil {
		return val, err
	}
	return val, nil
}

func GetString(bin []byte, offset uint64) string {
	str := ""
	for bin[offset] != 0 {
		str += string(bin[offset])
		offset++
	}
	return str
}
func GetCoffString(bin []byte, offset uint64) string {
	str := ""
	var cnt uint64 = 0
	for cnt < 8 {
		if bin[offset+cnt] == 0 {
			break
		}
		str += string(bin[offset+cnt])
		cnt++
	}
	return str
}

func FromUint32ToLeBytes(val uint32) []byte {
	buf := make([]byte, 4)
	binary.LittleEndian.PutUint32(buf, val)
	return buf
}
