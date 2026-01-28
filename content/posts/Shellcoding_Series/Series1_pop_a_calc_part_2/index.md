---
title: Popping a calculator - 64 bit - Part 2/3
date: 2024-03-27
author: retr0ds
author_url: https://twitter.com/_retr0ds_
categories:
  - Reversing
tags:
  - Blog
  - Shellcode
  - Windows
  - Series
  - Pop_a_calc

series: ["Shellcoding"]
series_order: 3
---


## Writing the Shellcode x64


This part of the blog covers the 64 bit shellcode to pop a calculator. Here I would be explaining my approach at writing source, you can skip right down to the bottom if you just want the compilation information [here](#compiling-64-bit)

For the source code you can visit the [github repo](https://github.com/retr0ds/Malware-learning/blob/main/shellcode/pop_calculator/x64/pop_calc.asm)

## Get The Kernel Base Address

This is the assembly that I ended up writing to get the `kernel32 base`

```x64!=
xor rax, rax
xor rcx, rcx
mov rcx, gs:[rax + 0x60] ; Address of PEB is loaded
mov rcx, [rcx+0x18]      ; Address of PEB_LDR_Module is loaded
mov rcx, [rcx+0x20]      ; Address of InMemoryOrderModuleList is loaded this is pointing to kernelbase.dll
mov rcx, [rcx+ 0x00]     ; Pointing to ntdll's ldr_data_table_entry
mov rcx, [rcx + 0x00]    ; kernel32.dll's ldr_data_table_entry is now referenced
mov rcx, [rcx+0x20] 	  ; base Address of kernel32.dll is now loaded
mov r10, rcx             ; r10 and rcx have kernel32 base
```

Now looking at this it might not be that comprehensible, so I'll try my best to explain it in the simplest terms

**Line 1 & 2** - Are pretty obvious we are zero'ing out the rax and rcx registers

**Line 3** - We load the `PEB` base address using the offset from the `gs` register into `rcx`

For the people that are familiar with basic windows internals you might be familiar with the `gs` register.
For the ones new to WinRev

***What is gs and fs?***


In earlier days of computing, there was a need for **segment registers** like some of which you might have heard of like `cs`(code segment) `es`(extra segment),`ss`(stack segment) ,`ds`(data segment) etc. 

These registers were born out of **necessity** to keep track of these **segments and hold their addresses** back when memory paging wasn't introduced to manage memory. 

So they used to keep these registers as base for segments and continue referencing memory at particular **offsets** from these registers to refer to various resources and code in appropriate sections.

But when memory paging came by the need for these registers were obsolete, and yet they are still present in Intel Architecture purely for backwards compatibility reasons and are still supported in different forms.

Windows specifically uses a few segment registers like `fs` and `gs` to keep track of certain important structures related to a process like the PEB and TEB.

You can read up more on PEB and TEB on the internet
But in simple words let's look at some

#### Some important Windows Data Structures (TIB/PEB/TEB)


**TIB** - [Thread Information Block](https://en.wikipedia.org/wiki/Win32_Thread_Information_Block#:~:text=The%20Thread%20Information%20Block%20)   - was used for the non WindowsNT versions, to hold basic process information. Widnows still supports it for backwards compatibilty reasons.

**PEB** - [Process Environment Block](https://ntopcode.wordpress.com/2018/02/26/anatomy-of-the-process-environment-block-peb-windows-internals/) - The Process Environment Block structure contains the process wide data structures which include global context, startup parameters, data structures for the program image loader, the program image base address, and synchronization objects

**TEB** - [Thread Environment Block]((https://en.wikipedia.org/wiki/Win32_Thread_Information_Block#:~:text=The%20Thread%20Information%20Block%20)) - Is an extentsion of the TIB and hence TEB and TIB are used synonymously. The TEB is the structure for Windows NT, 2000, XP, Vista, 7, 8, 10 and 11. 


In 32 bit, the `fs` register is used and this is used to point to the TIB of a given thread
These are the structure offsets inside TIB at which we can find various other important structural fields

**FS:[0x00]** : Current SEH Frame
**FS:[0x18]** : TEB (Thread Environment Block)
**FS:[0x20]** : PID
**FS:[0x24]** : TID
**FS:[0x30]** : PEB (Process Environment Block)
**FS:[0x34]** : Last Error Value

In 64 bit, the `gs` regsiter is used in place of `fs` to keep track of the TIB structure

**GS:[0x30]** : TEB
**GS:[0x40]** : PID
**GS:[0x48]** : TID
**GS:[0x60]** : PEB

Now using these registers and offset we can find our way into the PEB of any given windows binary.


**Line 4** - Now `rcx` which holds the base to `PEB` is added with `0x18` to get to the offset of `PEB_LDR_DATA`

**About PEB and PEB_LDR_DATA structure**

**PEB Structure**


As mentioned easlier, the `PEB` structure contains various information about a particular process like the base address, if it is being debugged or not, any inherited flags from other parent processes etc.

![image](https://hackmd.io/_uploads/Bkl9OzFJC.png)
![image](https://hackmd.io/_uploads/BJcj_GKkR.png)
[Source](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/pebteb/peb/index.htm)



But the one we are most interested in is the `PEB_LDR_DATA`.

The **PEB_LDR_DATA** structure is the defining record of which user-mode modules are loaded in a process. Each process has one `PEB_LDR_DATA` structure associated with it. Its address is kept in the Ldr member of the process’s PEB.
**PEB_LDR_STRUCTURE**

```cpp=
typedef struct _PEB_LDR_DATA
{
     ULONG Length;
     UCHAR Initialized;
     PVOID SsHandle;
     LIST_ENTRY InLoadOrderModuleList;
     LIST_ENTRY InMemoryOrderModuleList;
     LIST_ENTRY InInitializationOrderModuleList;
     PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;
````

As you can see it contains pointers to three important **linked lists**

Namely,
- **InLoadOrderModuleList**
- **InMemoryOrderModuleList**
- **InInitializationOrderModuleList**

They hold information about the modules (**dlls**) that are loaded by a proces

These are linked lists which share the same elements but they are just linked in a different order as suggested by their names

To explain them in brief I shall site it from a book - 

**Source** - The art of memory forensics book

- **InLoadOrderModuleList** - This linked list organizes modules in the order in which they are loaded into a process. Because the process executable is alwyas first to load in the process address space, its entry is first in this list.

- **InMemoryOrderModuleList** - This linked list organizes modules in the order in which they appear in the process's virtual memory layout. The last DLL to load may end up first in memory due to ASLR and other factors

- **InIntializationOrderModuleList** - This linked list organizes the modules in the order in which their DLL Main was executed. Just because a dll in loaded doesn't mean the DllMain is always called. For example, when we load a dll as a data file or as a resource.


**Line 5** - Now The address to the `First Link` of the linked list of InMemoryOrderModuleList is loaded. 

The offset is at `0x20` for 64 bit

![image](https://hackmd.io/_uploads/S1SK6QKyR.png)

The first link is pointing to an entry about `Kernelbase.dll`, so at the offset `0x20` we have **LDR_TABLE_ENTRY** structure
***Why InMemoryOrderModuleList?*** 

Well,
In all windows versions, the second and third DLLs in the linked list of `InMemoryOrderModuleList` is always `ntdll.dll` and `kernel32.dll`. 

We can also accomplish this using `InLoadOrderModuleList` however, the order of DLLs were changed from Vista onwards, so this doesn't ensure portability of shellcode.

Hence we stick with `InMemoryOrderModuleList`

Now after executing line 5 rcx points to the **[LDR_DATA_TABLE_ENTRY](https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/api/ntldr/ldr_data_table_entry/index.htm?tx=179,185)** of `kernelbase.dll`

**Line 6** - Now we load the address of the `second entry` into the `rcx` , which now holds the base to ntdll (as the first entry was already `kernelbase.dll` and it was pointed to by)

**LDR_TABLE_DATA_STRUCTURE**

![image](https://hackmd.io/_uploads/rJuiBVF1C.png)

The way it works is as depicted below


[Source](https://imphash.medium.com/windows-process-internals-a-few-concepts-to-know-before-jumping-on-memory-forensics-part-2-4f45022fb1f8)


Because we started accessing from the `InMemoryOrderModuleList` it keeps pointing to the next `InMemoryOrderModuleList` entry in the `LDR_DATA_TABLE_ENTRY` structure. Hence we are able to retrieve ntdll's `LDR_DATA_TABLE_ENTRY` structure by just calling offset 0

**LINE 7** - Similar to line 6 we now load the next dll (ie) the third dll **in memory order**.

**LINE 8** - Now we load the base of `kernel32.dll` at offset `0x20`

Now you may wonder, why is it at `0x20` and not `0x30` as shown in the `LDR_DATA_TABLE_ENTRY` structure above

That because of the very reason mentioned earlier, even though we got to the kernel32.dll's `LDR_DATA_TABLE_ENTRY` by calling offset-0x00 , we used a pointer to the **LIST_ENTRY** `InMemoryOrderLinks` and not to the start of the structure.

Now to acess the DLL Base we need to find the relative offset from The `InMemoryOrderLinks` entry. Which ends up being **0x30 - 0x10 = 0x20**

So now `rcx` and `r10` holds the` base address` of the `kernel32.dll`

**Line 9** - It just copies the value inside rcx into r10 for future uses


## Get the address to the Export table

```x64!=
mov ecx, [rcx + 0x3c]     ; Find RVA to PE header
add rcx, r10              ; Points to the PE header
;mov rcx, [rcx + 0x78]    ; RVA of Export table directory
mov ecx, [rcx + 0x88]     ; RVA of Export table directory
add rcx, r10              ; Export table directory address loaded
xor r9, r9
mov r9d, [rcx + 0x1c]     ; RVA Export Address Table
add r9, r10               ; Address to export Address Table
xor r11, r11
mov r11d, [rcx + 0x20]    ; RVA Export Name pointer table address 
add r11, r10              ; Adrdess of Export Name pointer table 
xor r12, r12              
mov r12d, [rcx + 0x24]    ; RVA of Ordinal Table
add r12, r10              ; Address of Ordinal Table
```

Here Initially rcx and r10 hold the base of the kernel32 dll

**Line 1** - Here we find the `RVA (Relative virtual address from the base of Kernel32)`, to the the PE Header
The offset of `0x3c` is never changed and remains the same in the PE format, as it is used to get to the `PE header`. 

![image](https://hackmd.io/_uploads/BJSle14gC.png)


Enough being side tracked, but as you can see in the image, the letter PE show up at the `RVA 0xE8` and `the offset/the RVA` of this can always be found at `0x3C` from the base.

![image](https://hackmd.io/_uploads/S1Ym-k4g0.png)


**Line 2** - Now we just add this offset (in our case E8) to the base of kernel32 dll to get the pointer to the PE header

**Line 3 & 4** - You may notice that line 3 is commented out and it has been given the same  comment as RVA of `Export Table Directory` as similar to line 4. Now I don't know the reason why, but in our case when I used tools such as `PE VIEW` and `CFF Explorer` both the tools showed the offset to find the `RVA(Relative virtual address from the base of the dll)` for `Export Table Directory` as `0x88` from the PE header. 

But, in the countless blogs that I did refer to and did take notes from as I was researching on shellcode and how it works, and many other windows related blogs all of them mention the `RVA` to be found at the `offset` **`0x78`** and not at **`0x88`**. 

So if someone kind enough to know the reason behind this is out there, feel free contact me and help me understand this 😭😭 and I'll edit this blog and put out the explanation as well.

But yes, that being said, the RVA for `kernel32.dll`'s in this particular case is at the offset 0x88 from the PE header, so rn we load that and move it into ecx and add it with r10 the `kernel32.dll`'s base address.

**Line 5** - Next we need to find the `Export Table Address`. Now you may wonder why is there a need for `Export Table Directory` and `Export Table` as two separate things. Why couldn't we just have the Export Table as a single entity so that we could just take the address refering to the name directly.

Well, the way windows has organized is not just a simple` Export Table` rather, it's a well defined `structure` that has general information with regards to exports furthermore it has three important table **pointers** pertaining to the sole purpose of keeping track of what all functions and modules are being exported out of a binary.

![image](https://hackmd.io/_uploads/r1jQng4xR.png)
source: [Export Address Table (EAT)](https://ferreirasc.github.io/PE-Export-Address-Table/)

- Export Address Table pointer
    - It contains the RVA to the list of exported functions. And an associated ord value. The ord value can be used to find the RVA of the exported function
- Name Pointer Table
    - It contains the names of the exported functions and associated address of this name string in memory. This table can be parsed to find the address to a particular function's address
- Ordinal Table
    - It contains the address of the various symbols and an associated ordinal value


So, these `3 tables` are interconnected and are needed for a succesful retreival of an exported function's address.


**Line 6, 7 and 8** - Now we get the register `r9` that is going to hold the address of the` Export Address Table` ready. And the `RVA`(Relative Virtual Address from the base of the kernel32.dll) to the export address table at an offset of `0x1c` from the address of` Export table directory`.This `RVA` is always a dword hence we stored it under `r9d`. And finally we add this `RVA` to the base of `kernel32.dll` to get the address to `Export Address Table`.


**Line 9, 10 and 11** - Now we get the register `r11` that is going to hold the address of the  ready. And the `RVA`(Relative Virtual Address from the base of the kernel32.dll) to the Name Pointer Table at an offset of 0x20 from the address of `Export table directory`. This `RVA` is always a dword hence we stored it under `r11d`.And finally we add this `RVA` to the base of `kernel32.dll` to get the address to `Name pointer table`.

**Line 12, 13 and 14** - Now we get the register `r12` that is going to hold the address of the  ready. And the `RVA`(Relative Virtual Address from the base of the kernel32.dll) to the Ordinal Table at an offset of 0x24 from the address of `Export table directory`. This `RVA` is always a dword hence we stored it under `r12d`.And finally we add this `RVA` to the base of `kernel32.dll` to get the address to `Ordinal Table`.


Summary of registers so far:

**r10** - Holds kernel32.dll's base
**r9** - Holds the Export Address Table pointer
**r11** - Holds Name Pointer Table Address
**r12** - Holds Ordinal Table Address



## Find the Base address of the WinExec function

```x64!=
xor rcx, rcx                  ; rcx is cleared
mov rcx, 0x7                  ; Length of WinExec is loaded into rcx
mov rax, 0x00636578456e6957   ; "\00cexEniW" is loaded into rax
push rax                      ; The string name is pushed onto the stack
push rcx                      ; Length is pushed onto the stack
call dynamic_api_resolve      ; dynamic_api_resolve label is called
mov r14, rax                  ; return address of the WinExec is put into r14
jmp next                      ; we jump to the next label

dynamic_api_resolve:
pop rbx                       ; return address is stored in rbx
pop rcx                       ; Length of the api is stored into rcx
xor rax, rax                  ; rax is cleared
mov rdx, rsp                  ; Move the address of name of the api into rdx
push rcx                      ; Length of the api is pushed onto the stack

loop:

mov rcx, [rsp]                ; The counter is being refreshed each time
xor rdi, rdi                  ; clear rdi for getting the name
mov edi, [r11 + rax * 4]      ; RVA of function name symbol  = Address of Name Pointer Table + counter * 4
add rdi, r10                  ; Address of  Function name symbol = RVA of function name symbol + base address 
mov rsi, rdx                  ; moving string to be compared into rsi

repe cmpsb                    ; comparing strings in rdi and rsi
je get_addr                   ; If equal we jump to get the address
inc rax                       ; Else increment counter
jmp loop                      ; jump back into loop


get_addr:
pop rcx                       ; Remove string length from top of stack
mov ax, [r12 + rax * 2]       ; Ordinal number of kernel 32 API (WinExec) = Adress of ordinal table + Counter * 2

mov eax, [r9 + rax * 4]       ; RVA of API = Address of Export Address Table + Ordinal number of WinExec * 4
add rax, r10                  ; Address of the API = RVA of API + base address
push rbx                      ; Pushing the Return Address back onto the stack
ret
```

**Line 1 & 2** - We start off with clearing out `rcx` register and set it to be `0x7` which is `len("WinExec")`

**Line 3** - It's `"WinExec\00"` in little endian moved into `rax`

**Line 5, 6 & 7** - Now we push the `"WinExec\00"` first followed by the length and call our `dynamic_api_resolve` label

Continuing with the control flow,

**Line 11** - We initially store the return address at the top of the stack and store it in `rbx`.

**Line 12 - 15** - Next value on top of the stack is the length that we pushed. That is being stored back in `rcx`, then `rax` is cleared. Now that the length is popped, the value at `rsp` (ie the top of the stack) is now the string of `'WinExec'`. The address of `rsp` is put into `rdx`, and `rcx` is pushed back onto the stack.

**Line 17**: Defines the start of a label which is used to loop

**Line 19 - 23** : We move the counter into `rcx`. Clear `rdi` for future purposes.Now remember, `r11` holds the `Address of the Name Pointer Table`. 

So, we add Address of Name pointer table + a counter (this we are mainting to keep track of which index of the Name pointer table is the symbol of our WinExec function at)

And this counter is `multiplied by 4` because all the RVA values inside this function is stored in `dword` format.

So, right now we load the `RVA of the string into edi`, and adding the `kernel32 base` to get the address of the actual string. We keep this arbitrary string in rdi.

`rdx` had our `"WinExec"` whose address is now being moved into `rsi`

**Line 25 - 28** - 
`repe cmpsb` is executed. Now this is a instruction which compares the string values inside `rdi` and `rsi` and sets the zero flag accordingly. It compares it byte by byte, but it's all masked under the single instruction of `repe cmpsb`.

Now `if the strings are equal` then we go ahead and jump to `get_addr`. Which we'll get to in a bit. But if it is not equal then we increment the counter value by 1, to go to the next `RVA` of the next string. And we jump `back to loop` ie (line 17)

**Line 31 - 33** - label `get_addr` is defined. Now as we know, the top of the stack contains the length of the string `"WinExec"`. We pop this from the top of the stack back into `rcx`.

Now we need to find the `ordinal number` of the particular `WinExec`. And ordinal number is simply put an `index` that windows maintains for each and every export. 

Think of it as a `process ID` but for exported functions. Each exported function has a `unique ID` which windows uses to reference the respective functions.
And this ordinal number is stored as a `WORD`. Like so,

![image](https://hackmd.io/_uploads/rJG6BG4lR.png)

The names might look too confusing, but as of now just focus on Name RVA and it's type as shown below in the image, `Name Ordinal` and it's type and `Function RVA` and it's type in the image

So the ordinal numbers are arranged in order as you can see, and a corresponding `ordinal number` can be found out using the corresponding `counter variable`.

Because we kept track of `rax`, the `index of the RVA` of the function, now we can find the ordinal numebr using the same `rax` counter. 

All we have to do is just take this `counter/index` and `multiply it by 2` because of `WORD` and then add it to the base address of the `orindal table`. 

Now derefencing this calculated pointer would get us the ordinal number of the appropriate name string. Because ordinal numbers are stored as words, we stored it back in `ax`


**Line 35 - 38** - Now we take this ordinal number and multiply it by 4 (Function RVA is stored as `DWORD`) and add this to the base of the `Export Address Table` to get the function `RVA` of our desired function which is `"WinExec"`

We now take this `RVA` and add it with `r10`(the `kernel32.dll`'s) base address to finally get the address of the desired API and store it under the `rax` register. (The return value of any call function is stored under `rax`). Now we push the `rbx`(the register that held on to the return address) and execute `ret`.

Executing `ret` would take us back to 

**Line 7 & 8** - Now address of the `WinExec` function inside `rax` is moved into the `r14` register and we now jump to a label called next


## Load the arguments into the WinExec function

```x64!=
;------------------------now r14 has our API -----------------------------------

next:
xor rcx, rcx                  ; clears out rcx   
mul rcx                       ; rax, rdx and rcx are 0

push rax                      ; Null Terminate string on stack
mov rax, 0x6578652e636c6163   ; Moving "exe.clac" into rax
push rax

mov rcx, rsp                  ; into first argument
inc rdx                       ; Argument to winEXe show_Normal
```

For this part we shall refer to the msdn documention on [WinExec](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec)

And as we,

![image](https://hackmd.io/_uploads/HyytyQ4gR.png)

We need to give 
1) the cmdline string of the program that we want to run
2) The cmdshow argument (this is basically controls how to open the program in what typ eof window) We shall still with just the most basic `show_window_normal` which holds the value 1 as it can be seen [here](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow).

**Line 1 - 3** - We now reach the next label. `rcx` is cleared and we use mul rcx to also clear rax, rdx as well

**Line 5 - 7** - Now that `rax` is 0, we just push it onto the stack to act as a `null terminator` for the upcoming string that we are about to push.

Then we mov `0x6578652e636c6163` which is `calc.exe` in little endian. Now we push it onto the stack as well

Then we load the first argument into rcx, which is at the top of the stack. The windows calling convention goes like `rcx`, `rdx`, `r8`, `r9` .


Now we increment that value of `rdx` by 1, setting 1 as the `second argument`.

## Call the function

```x64!=
sub rsp, 0x20
call r14
```

Here we do `sub rsp, 0x20`. Because I learnt `WinExec clobbers` the first 32 bytes on the stack as it is a function that is only to be in use for `16 bit mode` and any system running in either 32 or 64 bit mode should use `CreateProcess` as mentioned in the above image. So this extra space that we create acts as a `safety net` to prevent it from clobbering our useful bytes.

Now we go ahead and call `r14` which holds the address of WinExec.

That brings us to the end of our x64 shellcode.

## Compiling 64 bit

## Source Code

The full source and the associated files for this can be found here on my github - 
[x64 Assembly to pop a calculator](https://github.com/retr0ds/Malware-learning/blob/main/shellcode/pop_calculator/x64/)

### Assemble 

To compile the shellcode and get the object file we can use any assembler, I prefer `nasm`:

```bash
nasm -f win64 pop_calc.asm -o pop_calc.o
```

### Get Payload bytes

This is not necessary to just compile and run the shellcode. But, assuming we want to use this as `payload`, this is the one-liner used to generate the instruction bytes

```bash
for i in $(objdump -D pop_calc.o | grep "^ " | cut -f2); do echo -n "\x$i" ; done
```

### Link
Before running this shellcode as such we would requrire `linking`, which can be done by
```bash
ld -m i386pep pop_calc.o -o pop_calc.exe
```
### To Run
```bash
pop_calc.exe
```

