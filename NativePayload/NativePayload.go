package NativePayload

import (
	"golang.org/x/sys/windows"
	"log"
	"os"
	"time"
)

func NativeP2(shellcode []byte) {

	var _MemAdd uintptr
	var out uint32

	ProcessHandle, err := windows.OpenProcess(0x001F0FFF, false, uint32(os.Getpid()))
	if err != nil {
		log.Fatal(err)
	}
	err1 := windows.VirtualProtectEx(ProcessHandle, _MemAdd, uintptr(len(shellcode)), 0x40, &out)
	if err1 != nil {
		log.Fatal(err1)
	}
	time.Sleep(1 * time.Hour)
	err2 := windows.VirtualProtectEx(ProcessHandle, _MemAdd, uintptr(len(shellcode)), 0x10, &out)
	if err2 != nil {
		log.Fatal(err2)
	}
}
