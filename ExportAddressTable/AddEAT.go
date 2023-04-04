package ExportAddressTable

import (
	"github.com/Binject/debug/pe"
	"github.com/hillu/go-ntdll"
	"golang.org/x/sys/windows"
	"log"
	"strings"
	"syscall"
	"unsafe"
)

const (
	SECTION_MAP_EXECUTE = 0x0008
	SECTION_MAP_READ    = 0x0004
	SECTION_QUERY       = 0x0001
)

type IMAGE_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type IMAGE_DATA_DIRECTORY struct {
	VirtualAddress uint32
	Size           uint32
}

type IMAGE_OPTIONAL_HEADER64 struct {
	Magic                       uint16
	MajorLinkerVersion          byte
	MinorLinkerVersion          byte
	SizeOfCode                  uint32
	SizeOfInitializedData       uint32
	SizeOfUninitializedData     uint32
	AddressOfEntryPoint         uint32
	BaseOfCode                  uint32
	ImageBase                   uint64
	SectionAlignment            uint32
	FileAlignment               uint32
	MajorOperatingSystemVersion uint16
	MinorOperatingSystemVersion uint16
	MajorImageVersion           uint16
	MinorImageVersion           uint16
	MajorSubsystemVersion       uint16
	MinorSubsystemVersion       uint16
	Win32VersionValue           uint32
	SizeOfImage                 uint32
	SizeOfHeaders               uint32
	CheckSum                    uint32
	Subsystem                   uint16
	DllCharacteristics          uint16
	SizeOfStackReserve          uint64
	SizeOfStackCommit           uint64
	SizeOfHeapReserve           uint64
	SizeOfHeapCommit            uint64
	LoaderFlags                 uint32
	NumberOfRvaAndSizes         uint32
	DataDirectory               IMAGE_DATA_DIRECTORY
}

type PIMAGE_NT_HEADERS struct {
	Signature      uint32
	FileHeader     IMAGE_FILE_HEADER
	OptionalHeader IMAGE_OPTIONAL_HEADER64
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type LARGE_INTEGER struct {
	LowPart  uint32
	HighPart int32
	QuadPart int64
}

var (
	RVA2VA = syscall.MustLoadDLL("DbgHelp.dll").MustFindProc("ImageRvaToVa")
)

func GetPEBNtdll() uintptr {
	var KnownDllsNtDllName UNICODE_STRING
	var p1 ntdll.ObjectAttributes
	var SectionHandle ntdll.Handle
	temp, _ := syscall.UTF16PtrFromString("\\KnownDlls\\ntdll.dll")
	hNtdll, _ := windows.LoadLibrary("ntdll.dll")
	NtMapViewOfSection, _ := windows.GetProcAddress(hNtdll, "NtMapViewOfSectionEX")
	RtlInitUnicodeString, _ := windows.GetProcAddress(hNtdll, "RtlInitUnicodeString")
	_, _, err2 := syscall.SyscallN(RtlInitUnicodeString,
		uintptr(unsafe.Pointer(&KnownDllsNtDllName)),
		uintptr(unsafe.Pointer(temp)))
	if err2.Error() != "The operation completed successfully." {
		log.Fatal("[-] RtlInitUnicodeString失败 ->", err2)
	}
	ObjectAttributes := ntdll.ObjectAttributes{
		Length:                   uint32(unsafe.Sizeof(p1)),
		RootDirectory:            0,
		Attributes:               ntdll.OBJ_CASE_INSENSITIVE,
		ObjectName:               (*ntdll.UnicodeString)(&KnownDllsNtDllName),
		SecurityDescriptor:       nil,
		SecurityQualityOfService: nil,
	}
	ntdll.NtOpenSection(
		&SectionHandle,
		SECTION_MAP_EXECUTE|SECTION_MAP_READ|SECTION_QUERY,
		&ObjectAttributes)
	//设置要开始映射的偏移量
	SectionOffset := LARGE_INTEGER{
		LowPart:  0,
		HighPart: 0,
	}
	//设置所需的基址和要映射的字节数
	var ViewSize uint32
	var ViewBase uintptr
	p2 := windows.CurrentProcess()
	syscall.SyscallN(
		NtMapViewOfSection,
		uintptr(unsafe.Pointer(&SectionHandle)),
		uintptr(unsafe.Pointer(&p2)),
		ViewBase,
		0,
		0,
		uintptr(unsafe.Pointer(&SectionOffset)),
		uintptr(unsafe.Pointer(&ViewSize)),
		1,
		0,
		windows.PAGE_EXECUTE_READ)
	if ViewBase == 0 {
		log.Fatal("[-] NtMapViewOfSection失败")
	}
	return ViewBase
}

func GetProcAddressFromEAT(DllBase uintptr, FunctionName string) uintptr {
	var NtHeaders PIMAGE_NT_HEADERS
	var NumberOfNames uint32
	var ExportDirectory IMAGE_EXPORT_DIRECTORY
	var Functions1 *uint32
	var ProcAddress uintptr
	var Name *int8
	DosHeader := (*pe.DosHeader)(unsafe.Pointer(DllBase))
	_, _, err := RVA2VA.Call(uintptr(unsafe.Pointer(&NtHeaders)), DllBase, uintptr(DosHeader.AddressOfNewExeHeader), 0)
	if err.Error() != "The operation completed successfully." {
		log.Fatal(err)
	}
	DataDirectory := NtHeaders.OptionalHeader.DataDirectory
	VirtualAddress := DataDirectory.VirtualAddress

	if VirtualAddress == 0 {
		return 0
	}

	RVA2VA.Call(uintptr(unsafe.Pointer(&ExportDirectory)), DllBase, uintptr(VirtualAddress))
	NumberOfNames = ExportDirectory.NumberOfNames

	if NumberOfNames == 0 {
		return 0
	}

	Functions, _, _ := RVA2VA.Call(uintptr(unsafe.Pointer(Functions1)), DllBase, uintptr(ExportDirectory.AddressOfFunctions), 0)
	Names, _, _ := RVA2VA.Call(uintptr(unsafe.Pointer(Functions1)), DllBase, uintptr(ExportDirectory.AddressOfNames), 0)
	Ordinals, _, _ := RVA2VA.Call(uintptr(unsafe.Pointer(Functions1)), DllBase, uintptr(ExportDirectory.AddressOfNameOrdinals), 0)

	for true {
		Names1 := *(*[]uint32)(unsafe.Pointer(Names))
		Functions2 := *(*[]uint32)(unsafe.Pointer(Functions))
		Ordinals1 := *(*[]uint32)(unsafe.Pointer(Ordinals))
		Name1, _, _ := RVA2VA.Call(uintptr(unsafe.Pointer(Name)), DllBase, uintptr(unsafe.Pointer(&Names1[NumberOfNames-1])), 0)
		Name2 := *(*string)(unsafe.Pointer(&Name1))
		if strings.Compare(Name2, FunctionName) == 0 {
			ProcAddress, _, _ = RVA2VA.Call(ProcAddress, DllBase, uintptr(unsafe.Pointer(&Functions2[Ordinals1[NumberOfNames-1]])), 0)
			return ProcAddress
		}
	}

	return ProcAddress
}
