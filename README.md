![](https://socialify.git.ci/nu1r/GoLangUnhooker/image?font=Raleway&language=1&logo=https%3A%2F%2Fs1.ax1x.com%2F2022%2F09%2F12%2FvXqOUI.jpg&name=1&owner=1&pattern=Floating%20Cogs&stargazers=1&theme=Light)

# 用户层脱钩
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

# Threadless Process Injection

来自 BsidesCymru 2023 演讲 [Needles Without the Thread](https://pretalx.com/bsides-cymru-2023-2022/talk/BNC8W3/)



# TODO

+ 更新更多的EDR绕过技术;
+ 实现 D/Invoke 中的技术;

# 参考

+ https://roberreigada.github.io/posts/playing_with_an_edr/;
+ https://s3cur3th1ssh1t.github.io/A-tale-of-EDR-bypass-methods/;
+ https://github.com/am0nsec/HellsGate;
+ https://ethicalchaos.dev/2020/05/27/lets-create-an-edr-and-bypass-it-part-1/;
+ https://ethicalchaos.dev/2020/06/14/lets-create-an-edr-and-bypass-it-part-2/;
+ https://thewover.github.io/Dynamic-Invoke/;
+ https://j00ru.vexillium.org/syscalls/nt/64/;