package main

import "UnhookingGoLang/SharpUnhooker"

func main() {
	//NtdllUnhook.Dll()
	//
	//syscall.LoadLibrary("SharpUnhooker/SharpUnhooker.dll")
	//
	//shellcode := []byte{}
	//ThreadlessInject.Inject("Crypt32", "CertEnumSystemStore", 1372, shellcode)

	SharpUnhooker.Unhook()
}
