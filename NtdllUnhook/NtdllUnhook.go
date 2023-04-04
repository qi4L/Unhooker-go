package NtdllUnhook

import (
	"bytes"
	"fmt"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

const (
	GENERIC_READ                = 0x80000000
	FILE_SHARE_READ             = 0x00000001
	NULL                        = 0
	OPEN_EXISTING               = 3
	SEC_IMAGE                   = 0x01000000
	IMAGE_SIZEOF_SHORT_NAME     = 8
	IMAGE_SIZEOF_SECTION_HEADER = 40
)

var (
	oldProtection uintptr
)

type PIMAGE_DOS_HEADER struct {
	e_magic    uintptr     // Magic number
	e_cblp     uintptr     // Bytes on last page of file
	e_cp       uintptr     // Pages in file
	e_crlc     uintptr     // Relocations
	e_cparhdr  uintptr     // Size of header in paragraphs
	e_minalloc uintptr     // Minimum extra paragraphs needed
	e_maxalloc uintptr     // Maximum extra paragraphs needed
	e_ss       uintptr     // Initial (relative) SS value
	e_sp       uintptr     // Initial SP value
	e_csum     uintptr     // Checksum
	e_ip       uintptr     // Initial IP value
	e_cs       uintptr     // Initial (relative) CS value
	e_lfarlc   uintptr     // File address of relocation table
	e_ovno     uintptr     // Overlay number
	e_res      [4]uintptr  // Reserved words
	e_oemid    uintptr     // OEM identifier (for e_oeminfo)
	e_oeminfo  uintptr     // OEM information; e_oemid specific
	e_res2     [10]uintptr // Reserved words
	e_lfanew   uintptr     // File address of new exe header
}

type PIMAGE_NT_HEADERS64 struct {
	Signature      uintptr
	FileHeader     PIMAGE_FILE_HEADER
	OptionalHeader uintptr
}

type PIMAGE_FILE_HEADER struct {
	Machine              uintptr
	NumberOfSections     uintptr
	TimeDateStamp        uintptr
	PointerToSymbolTable uintptr
	NumberOfSymbols      int32
	SizeOfOptionalHeader uintptr
	Characteristics      uintptr
}

type PIMAGE_SECTION_HEADER struct {
	Name [IMAGE_SIZEOF_SHORT_NAME]byte
	Misc struct {
		PhysicalAddress uint32
		VirtualSize     uint32
	}
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLinenumbers uint32
	NumberOfRelocations  uint16
	NumberOfLinenumbers  uint16
	Characteristics      uint32
}

func IMAGE_FIRST_SECTION(ntheader *PIMAGE_NT_HEADERS64) *PIMAGE_SECTION_HEADER {
	return (*PIMAGE_SECTION_HEADER)(unsafe.Pointer(
		uintptr(unsafe.Pointer(ntheader)) +
			unsafe.Offsetof(PIMAGE_NT_HEADERS64{}.OptionalHeader) +
			ntheader.FileHeader.SizeOfOptionalHeader,
	))
}

func Dll(DllName string) {
	//sys GetCurrentProcessNu1r()(process uintptr)=Kernel32.GetCurrentProcess
	process := GetCurrentProcessNu1r()
	var mi windows.ModuleInfo
	//sys GetModuleHandleANu1r(lpModuleName uintptr)(ntdllModule uintptr)=Kernel32.GetModuleHandleA
	p1, _ := syscall.UTF16PtrFromString(DllName)
	ntdllModule := GetModuleHandleANu1r(uintptr(unsafe.Pointer(p1)))
	//sys GetModuleInformationNu1r(hProcess uintptr,hModule uintptr,lpmodinfo uintptr,cb uintptr)=Psapi.GetModuleInformation
	GetModuleInformationNu1r(
		process, ntdllModule,
		(uintptr)(unsafe.Pointer(&mi)),
		unsafe.Sizeof(mi),
	)
	ntdllBase := unsafe.Pointer(mi.BaseOfDll)
	p2, _ := syscall.UTF16PtrFromString("c:\\windows\\system32\\" + DllName)
	//sys CreateFileANu1r(lpFileName uintptr,dwDesiredAccess uintptr,dwShareMode uintptr,lpSecurityAttributes uintptr,dwCreationDisposition uintptr,dwFlagsAndAttributes uintptr,hTemplateFile uintptr)(ntdllFile uintptr)=Kernel32.CreateFileA
	ntdllFile := CreateFileANu1r(
		uintptr(unsafe.Pointer(p2)),
		GENERIC_READ,
		FILE_SHARE_READ,
		NULL,
		OPEN_EXISTING,
		0,
		NULL,
	)
	//sys CreateFileMappingWNu1r(hFile uintptr,lpFileMappingAttributes uintptr,flProtect uintptr,dwMaximumSizeHigh uintptr,dwMaximumSizeLow uintptr,lpName uintptr)(ntdllMapping uintptr)=Kernel32.CreateFileMappingW
	ntdllMapping := CreateFileMappingWNu1r(
		ntdllFile,
		NULL,
		windows.PAGE_READONLY|SEC_IMAGE,
		0,
		0,
		NULL,
	)
	//sys MapViewOfFileNu1r(hFileMappingObject uintptr,dwDesiredAccess uintptr,dwFileOffsetHigh uintptr,dwFileOffsetLow uintptr,dwNumberOfBytesToMap uintptr) (ntdllMappingAddress uintptr)=Kernel32.MapViewOfFile
	ntdllMappingAddress := MapViewOfFileNu1r(
		ntdllMapping,
		windows.FILE_MAP_READ,
		0,
		0,
		0,
	)
	p7 := 224 //hookedDosHeader.e_lfanew
	//hookedDosHeader := (*PIMAGE_DOS_HEADER)(unsafe.Pointer(&ntdllBase))
	p6 := uintptr(ntdllBase) + uintptr(unsafe.Pointer(&p7))
	hookedNtHeader := (*PIMAGE_NT_HEADERS64)(unsafe.Pointer(&p6))
	p5 := uintptr(unsafe.Pointer(&hookedNtHeader.FileHeader.NumberOfSections))
	NumberOfSections := (*int)(unsafe.Pointer(p5))
	Numberofsections1 := *NumberOfSections
	for i := 0; i < Numberofsections1; i++ {
		p3 := IMAGE_SIZEOF_SECTION_HEADER * i
		p4 := IMAGE_FIRST_SECTION(hookedNtHeader)
		p8 := uintptr(unsafe.Pointer(&p3)) + uintptr(unsafe.Pointer(&p4))
		hookedSectionHeader := (*PIMAGE_SECTION_HEADER)(unsafe.Pointer(&p8))

		if bytes.Equal(hookedSectionHeader.Name[:], []byte(".text\x00")) {
			//sys VirtualProtectNu1r(lpAddress uintptr,dwSize uintptr,flNewProtect uintptr,lpflOldProtect uintptr)(isProtected uintptr)=Kernel32.VirtualProtect
			isProtected := VirtualProtectNu1r(
				uintptr(unsafe.Pointer(&ntdllBase))+uintptr(unsafe.Pointer(&hookedSectionHeader.VirtualAddress)),
				uintptr(unsafe.Pointer(&hookedSectionHeader.Misc.VirtualSize)),
				windows.PAGE_EXECUTE_READWRITE,
				uintptr(unsafe.Pointer(&oldProtection)),
			)
			fmt.Println(isProtected)
			srcAddr := ntdllMappingAddress + uintptr(unsafe.Pointer(&hookedSectionHeader.VirtualAddress))
			dst := make([]byte, hookedSectionHeader.Misc.VirtualSize)
			addr := uintptr(unsafe.Pointer(&ntdllBase)) + uintptr(unsafe.Pointer(&hookedSectionHeader.VirtualAddress))
			copy(dst, (*[1 << 30]byte)(unsafe.Pointer(srcAddr))[:hookedSectionHeader.Misc.VirtualSize])
			copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:hookedSectionHeader.Misc.VirtualSize], dst)
			isProtected = VirtualProtectNu1r(
				uintptr(unsafe.Pointer(&ntdllBase))+uintptr(unsafe.Pointer(&hookedSectionHeader.VirtualAddress)),
				uintptr(unsafe.Pointer(&hookedSectionHeader.Misc.VirtualSize)),
				oldProtection,
				uintptr(unsafe.Pointer(&oldProtection)),
			)
		}

	}
	//sys CloseHandleNu1r(hObject uintptr) = Kernel32.CloseHandle
	CloseHandleNu1r(process)
	CloseHandleNu1r(ntdllFile)
	CloseHandleNu1r(ntdllMapping)
	CloseHandleNu1r(ntdllModule)
}
