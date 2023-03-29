package SharpUnhooker

import (
	"bytes"
	"debug/pe"
	"fmt"
	"log"
	"os"
	"syscall"
)

var (
	err            error
	ModuleFullPath string
	moduleBytes    []byte
)

var (
	textSectionNumber = 0
)

func JMPUnhooker(DLLname string) {
	//获取模块的文件路径
	if _, err = syscall.LoadLibrary(DLLname); err != nil {
		log.Fatal(err)
	}
	ModuleFullPath = "C:\\WINDOWS\\SYSTEM32\\" + DLLname
	//读取并解析模块，然后获取.TEXT节头
	if moduleBytes, err = os.ReadFile(ModuleFullPath); err != nil {
		log.Fatal(err)
	}
	originalModule, _ := pe.NewFile(bytes.NewReader(moduleBytes))
	fmt.Println(originalModule.ImportedLibraries())
	//for i, section := range originalModule.Sections {
	//	// 如果当前节表项的名称（Name）为 ".text"，则将 textSectionNumber 设置为当前节表项的序号
	//	if strings.EqualFold(section.Name, ".text") {
	//		textSectionNumber = i
	//		break
	//	}
	//}
	// 复制原始的.TEXT部分
}

func Unhook() {
	ListOfDLLToUnhook := []string{"ntdll.dll", "kernel32.dll", "kernelbase.dll", "advapi32.dll"}
	for _, DllName := range ListOfDLLToUnhook {
		JMPUnhooker(DllName)
	}

}
