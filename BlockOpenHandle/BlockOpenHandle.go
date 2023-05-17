package BlockOpenHandle

import (
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

const (
	SDDL_REVISION_1 = 1
	nullptr         = 0
)

var (
	err                error
	securityDescriptor *windows.SECURITY_DESCRIPTOR = nil
)

func SetProcessSecurityDescriptor() {
	// Define a security descriptor string in SDDL format
	// The following SDDL string denies all access to the process, except for the SYSTEM account and the process owner
	SDDL, _ := syscall.UTF16PtrFromString("D:P(D;OICI;GA;;;WD)(A;OICI;GA;;;SY)(A;OICI;GA;;;OW)")
	//sys ConvertStringSecurityDescriptorToSecurityDescriptorW(p1 uintptr,p2 uintptr,p3 uintptr,p4 uintptr)(p5 error)=Advapi32.ConvertStringSecurityDescriptorToSecurityDescriptorW
	ConvertStringSecurityDescriptorToSecurityDescriptorW(
		uintptr(unsafe.Pointer(SDDL)),
		SDDL_REVISION_1,
		uintptr(unsafe.Pointer(securityDescriptor)),
		nullptr)
	if err = windows.SetKernelObjectSecurity(windows.CurrentProcess(), windows.DACL_SECURITY_INFORMATION, securityDescriptor); err != nil {
		return
	}
	securityDescriptor1 := uintptr(unsafe.Pointer(securityDescriptor))
	windows.LocalFree(windows.Handle(securityDescriptor1))
}
