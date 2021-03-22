# Squishrunner静态版，基于InfectPE项目，静态修改PE程序，注入shellcode

## 使用方法：
1. 将squishqtpre.dll放在C:\fuzz\code目录下
2. 运行以下命令
```
  C:\fuzz\code\InfectPE-master\Release\InfectPE.exe Z:\fuzz\auts\yzf\spinboxes\release\spinboxes.exe Z:\fuzz\auts\yzf\spinboxes\release\spinboxes_injected.exe new
  ```

## 运行说明：
1. 植入的代码将监听指定端口（本地环境变量配置），用来和squishserver及squishrunner通信；
2. 运行后输出“EOF”，双击打开生成的spinboxes_injected.exe，出现防火墙弹框，选择“允许执行”，也可以查看其是否监听端口判断是否植入成功。

## 本地环境变量（按需修改）
```
setx SQUISH_PREFIX "C:\soft\squish_win32_msvc10"
setx SQUISH_LOG_PRELOAD_FILE "<stderr>"
setx SQUISH_LOG_WRAPPER_FILE "<stderr>"
setx SQUISH_LOG_PRELOAD_LEVEL "0"
setx SQUISH_LOG_WRAPPER_LEVE "0"
setx SQUISH_ATTACHABLE_PORT "9999"

在环境变量Path后追加Qt和squish的bin目录，如：
C:\Qt\4.8.3\bin;C:\soft\squish_win32_msvc10\bin
```

## shellcode解释：

```
		xor ecx, ecx
		mov eax, fs:[ecx + 0x30]; EAX = PEB
		mov eax, [eax + 0xc]; EAX = PEB->Ldr
		mov esi, [eax + 0x14]; ESI = PEB->Ldr.InMemOrder
		lodsd; EAX = Second module
		xchg eax, esi; EAX = ESI, ESI = EAX
		lodsd; EAX = Third(kernel32)
		mov ebx, [eax + 0x10]; EBX = Base address
		mov edx, [ebx + 0x3c]; EDX = DOS->e_lfanew
		add edx, ebx; EDX = PE Header
		mov edx, [edx + 0x78]; EDX = Offset export table
		add edx, ebx; EDX = Export table
		mov esi, [edx + 0x20]; ESI = Offset namestable
		add esi, ebx; ESI = Names table
		xor ecx, ecx; EXC = 0

		Get_Function:
		inc ecx; Increment the ordinal
		lodsd; Get name offset
		add eax, ebx; Get function name
		cmp dword ptr[eax], 0x50746547; GetP
		jnz Get_Function
		cmp dword ptr[eax + 0x4], 0x41636f72; rocA
		jnz Get_Function
		cmp dword ptr[eax + 0x8], 0x65726464; ddre
		jnz Get_Function
		mov esi, [edx + 0x24]; ESI = Offset ordinals
		add esi, ebx; ESI = Ordinals table
		mov cx, [esi + ecx * 2]; Number of function
		dec ecx
		mov esi, [edx + 0x1c]; Offset address table
		add esi, ebx; ESI = Address table
		mov edx, [esi + ecx * 4]; EDX = Pointer(offset)
		add edx, ebx; // EDX = GetProcAddress
		push edx;     // save GetProcAddress

		xor ecx, ecx; ECX = 0
		push ecx; 0
		push 0x41797261; aryA
		push 0x7262694c; Libr
		push 0x64616f4c; Load
		push esp; "LoadLibrary"
		push ebx; Kernel32 base address
		call edx; GetProcAddress(LL)
		add esp, 0x10;
			
		xor ecx, ecx; ECX = 0
		push ecx; 0
		push 0x6c6c642e
		push 0x65727074
		push 0x71687369
		push 0x7571735c
		push 0x65646f63
		push 0x5c7a7a75
		push 0x665c3a43; // C:\\fuzz\\code\\squishqtpre.dll
		push esp
		call eax
		add esp, 0x20
			
		pop edx;  // EDX = GetProcAddress

		push 0x6e6961
		push 0x4d6c6c44
		push 0x74736f70; // postDllMain
		push esp
		push eax
		call edx // GetProcAddress(postDllMain)
		call eax // call postDllMain
		add esp, 0xc
```
## 参考资料
1. https://securitycafe.ro/2016/02/15/introduction-to-windows-shellcode-development-part-3/
2. https://github.com/secrary/InfectPE
