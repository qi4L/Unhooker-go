package PatchInlineHooking

import (
	"golang.org/x/sys/windows"
	"log"
	"syscall"
	"unsafe"
)

const (
	NULL  = 0
	MB_OK = 0x00000000
)

var (
	p3                      uintptr
	pro                     uintptr
	messageBoxOriginalBytes [6]byte
	messageBoxAddress       uintptr
	err                     error
	library                 windows.Handle
	p1, _                   = syscall.UTF16PtrFromString("hi")
	bytesRead               = 0
	bytesWritten            = 0
)

func HookedMessageBox(hWnd uintptr, lpText uintptr, lpCaption uintptr, uType uintptr) {
	if pro, err = GetCurrentProcess(); err != nil {
		log.Fatal(err)
	}
	//sys WriteProcessMemory(p1 uintptr,p2 uintptr,p3 uintptr,p4 uintptr,p5 uintptr)(err error)=Kernel32.WriteProcessMemory
	err = WriteProcessMemory(pro, messageBoxAddress, uintptr(unsafe.Pointer(&messageBoxOriginalBytes)), unsafe.Sizeof(messageBoxOriginalBytes), uintptr(unsafe.Pointer(&bytesWritten)))
	if err != nil {
		log.Fatal(err)
	}
	p3, err = MessageBoxA(NULL, lpText, lpCaption, uType)
	if err != nil {
		log.Fatal(err)
	}
}

func Inline() {
	// 在钩子前显示消息框
	//sys MessageBoxA(p1 uintptr,p2 uintptr,p3 uintptr,p4 uintptr)(p5 uintptr,err error)=User32.MessageBoxA
	p3, err = MessageBoxA(NULL, uintptr(unsafe.Pointer(p1)), uintptr(unsafe.Pointer(p1)), MB_OK)
	if err != nil {
		log.Fatal(err)
	}
	if library, err = windows.LoadLibrary("user32"); err != nil {
		log.Fatal(library)
	}
	// 获取内存中MessageBox函数的地址
	if messageBoxAddress, err = windows.GetProcAddress(library, "MessageBoxA"); err != nil {
		log.Fatal(err, " GetProcAddress")
	}
	//sys GetCurrentProcess()(pro uintptr,err error)=Kernel32.GetCurrentProcess
	if pro, err = GetCurrentProcess(); err != nil {
		log.Fatal(err)
	}
	//sys ReadProcessMemory(p1 uintptr,p2 uintptr,p3 uintptr,p4 uintptr,p5 uintptr)(err error)=Kernel32.ReadProcessMemory
	if err = ReadProcessMemory(pro, messageBoxAddress, uintptr(unsafe.Pointer(&messageBoxOriginalBytes)), 6, uintptr(unsafe.Pointer(&bytesRead))); err != nil {
		log.Fatal(err, " ReadProcessMemory")
	}
	// 保存原始MessageBoxA函数的前6个字节-将需要解绑定
	HookedMessageBoxFunc := HookedMessageBox
	HookedMessageBoxFuncADD := &HookedMessageBoxFunc
	patch := make([]byte, 6)
	p4 := "\x68"
	p5 := "\xC3"
	copy(patch, (*[1]byte)(unsafe.Pointer(&p4))[:1])
	copy(patch[1:], (*[4]byte)(unsafe.Pointer(&HookedMessageBoxFuncADD))[:4])
	copy(patch[5:], (*[1]byte)(unsafe.Pointer(&p5))[:1])

	// 给MessageBoxA打补丁
	err = WriteProcessMemory(pro, messageBoxAddress, uintptr(unsafe.Pointer(&patch)), unsafe.Sizeof(patch), uintptr(unsafe.Pointer(&bytesWritten)))
	if err != nil {
		log.Fatal(err)
	}

	// 钩接后显示消息框
	p3, err = MessageBoxA(NULL, uintptr(unsafe.Pointer(p1)), uintptr(unsafe.Pointer(p1)), MB_OK)
}
