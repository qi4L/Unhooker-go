package EATUnhooker

import "C"
import (
	"bytes"
	"encoding/binary"
	"fmt"
	"golang.org/x/sys/windows"
	"io"
	"log"
	"os"
	"strings"
	"syscall"
	"unsafe"
)

const (
	MAX_PATH               = 260
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	ModuleFileName string
	pExport        int64
)

func NewPEReader(fileBytes []byte) (*PEReader, error) {
	r := bytes.NewReader(fileBytes)
	var err error
	pe := &PEReader{}
	err = binary.Read(r, binary.LittleEndian, &pe.dosHeader)
	if err != nil {
		return nil, err
	}
	r.Seek(int64(pe.dosHeader.e_lfanew), io.SeekStart)
	var ntHeadersSignature uint32
	err = binary.Read(r, binary.LittleEndian, &ntHeadersSignature)
	if err != nil {
		return nil, err
	}
	err = binary.Read(r, binary.LittleEndian, &pe.fileHeader)
	if err != nil {
		return nil, err
	}
	if pe.Is32BitHeader() {
		err = binary.Read(r, binary.LittleEndian, &pe.optionalHeader32)
	} else {
		err = binary.Read(r, binary.LittleEndian, &pe.optionalHeader64)
	}
	if err != nil {
		return nil, err
	}
	pe.imageSectionHeaders = make([]IMAGE_SECTION_HEADER, pe.fileHeader.NumberOfSections)
	for i := range pe.imageSectionHeaders {
		err = binary.Read(r, binary.LittleEndian, &pe.imageSectionHeaders[i])
		if err != nil {
			return nil, err
		}
	}
	pe.rawbytes = fileBytes
	return pe, nil
}

func (pe *PEReader) Is32BitHeader() bool {
	if pe.fileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 || pe.fileHeader.Machine == IMAGE_FILE_MACHINE_I386 {
		return true
	}
	return false
}

func readInt16(addr uintptr) int16 {
	return *(*int16)(unsafe.Pointer(addr))
}

func readInt32(addr uintptr) int32 {
	return *(*int32)(unsafe.Pointer(addr))
}

func Dll(DllName string) {
	var ModuleBase windows.Handle
	var hMods [1024]windows.Handle
	var cbNeeded uint32

	// 获取进程模块列表
	err := windows.EnumProcessModules(windows.CurrentProcess(), &hMods[0], uint32(len(hMods)), &cbNeeded)
	if err != nil {
		log.Fatal(err)
	}
	// 遍历模块列表查找指定模块
	numModules := int(cbNeeded / uint32(unsafe.Sizeof(hMods[0])))
	var szModName [MAX_PATH]uint16
	for i := 0; i < numModules; i++ {
		if err1 := windows.GetModuleFileNameEx(windows.CurrentProcess(), hMods[i], &szModName[0], MAX_PATH); err1 != nil {
			fmt.Printf("Error: %v\n", syscall.GetLastError())
			return
		}
		//fmt.Println(syscall.UTF16ToString(szModName[:]))
		if strings.Contains(strings.ToLower(syscall.UTF16ToString(szModName[:])), strings.ToLower(DllName)) {
			ModuleBase = hMods[i]
			ModuleFileName = syscall.UTF16ToString(szModName[:])
			break
		}
	}
	//fmt.Println(ModuleBase, ModuleFileName)
	if ModuleBase == 0 {
		log.Fatal("[-] Module is not loaded,Skipping...")
	}
	moduleRawByte, err := os.ReadFile(ModuleFileName)
	//fmt.Println(moduleRawByte)
	// Traverse the PE header in memory
	peHeader := readInt32(uintptr(ModuleBase) + 0x3C)
	//optHeaderSize := readInt16(uintptr(ModuleBase) + uintptr(peHeader) + 0x14)
	optHeader := int64(uintptr(ModuleBase) + uintptr(peHeader) + 0x18)
	magic := readInt16(uintptr(optHeader))
	if magic == 0x010b {
		pExport = optHeader + 0x60
	} else {
		pExport = optHeader + 0x70
	}
	// prepare module clone
	diskModuleParsed, _ := NewPEReader(moduleRawByte)
	var regionSize int
	var sizeOfHeaders int
	if diskModuleParsed.Is32BitHeader() {
		regionSize = int(diskModuleParsed.optionalHeader32.SizeOfImage)
		sizeOfHeaders = int(diskModuleParsed.optionalHeader32.SizeOfHeaders)
	} else {
		regionSize = int(diskModuleParsed.optionalHeader64.SizeOfImage)
		sizeOfHeaders = int(diskModuleParsed.optionalHeader64.SizeOfHeaders)
	}
	OriginalModuleBase, err2, err3 := syscall.MustLoadDLL("kernel32.dll").MustFindProc("VirtualAlloc").Call(0, uintptr(regionSize), MEM_COMMIT|MEM_RESERVE, PAGE_EXECUTE_READWRITE)
	if err3 != nil && err3.Error() != "The operation completed successfully." {
		log.Fatal(err2)
	}
	OriginalModuleBase1 := *(*[]byte)(unsafe.Pointer(OriginalModuleBase))
	copy((*[1 << 30]byte)(OriginalModuleBase1)[:sizeOfHeaders], moduleRawByte[:sizeOfHeaders])

	return
}
