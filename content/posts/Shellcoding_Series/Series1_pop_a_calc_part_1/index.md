---
title: Popping a calculator - Basic - Part 1/3
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
series_order: 2
---

Windows Shellcoding Series 1 - Part 1/3
===

# Popping a calculator

# Init()

Now in the series I would be covering both the **64 bit** and **32 bit versions** of the shellcode to pop a calculator and would go about explaining them both separately.


# The Approach


The basic idea of approach or the methodology in which I intend to approach writing this shellcode is the same for both 64 bit and 32 bit.

Now let's start by thinking backwards from the result as to figure out what we need in the shellcode to launch the calculator.

##  - Execute a calculator
     
The end goal of our current shellcode is that it needs to end in **launching a calculator**
For the exact purpose of executing/launching applications windows has the `WinExec` API which does exactly what we need


 
**source** : [MSDN WinExec Documentation](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winexec) 


So all we need to do is call `WinExec` with it's required parameters and we're done.
We could have also done it using `CreateProcessA` but that involves a lot more arguments and I wanted to use the most simplest approach to this shellcode
But, now this gets us thinking how do we go about calling `WinExec`?🤔

##  - How to call WinExec?

If we are normally programming we can just do a `WinExec()` with the necessary arguments

However, internally in assembly we do a `call register` where the register holds the addresss of the function that we are about to call

So in a nutshell,
To call any function we need an address
**An address to where this function is defined and loaded in memory**

So first we need to figure out where this `WinExec` Function is defined inside the system.

Now upon basic googling we find ***kernel32.dll*** to contain the function definition of ***`WinExec`*** . 

So now we need to go about finding where exactly inside kernel32 is this function Winexec defined

## - Finding WinExec inside kernel32

So now to get down to a few **Windows Reversing basics**, 
All windows executables need to follow the PE format which defines how a particular executable is to organize it's various data, like code, images, functions that it imports from other executables or libaries so on and so forth.

So, any windows executable (PE format) contains a lot of sections  out of which **two important** ones are the `Export Table` and `Import table`

These two tables store the information relating to the modules that are being imported by the binary and exported from the binary

In our case we need to look for `WinExec` inside `kernel32.dll` under the `Export Directory`, because whatever is being exported out of a dll is stored under the` Export Directory`.

This `Export directory` would contain information like the name of  the corresponding function (`WinExec` in our case) and the **offset** where we can find it

So summarising what we need to do now is 

1) to find the base address to the `kernel32.dll` function
2) then from there we can get to the `Export Address Directory` inside `kernel32.dll` 
3) then next we can get to the base address of the function `WinExec`

## - Getting base of kernel32.dll

Windows **creates/launches a thread to run any code**, even the arbitrary bytes such as this shellcode. And while doing so, it also associates a very **important data structure** to each thread that it runs and controls called the `TEB - The Thread Environment Block`. **This structure holds important information pertaining to a thread and the libraries/dlls it loads**. This `TEB` also points to another important strcuture associated to any such process and thread called the `PEB - Process Environment Block` which is maintained at a **constant offset from the TEB**. **Using this PEB** now we can find the base address of the `kernel32.dll`

Now this might be a bit confusing to the new ones here, the questions probably running through your mind is,

Sure, **there's a TEB associated to every running thread and running a thread is how windows runs the shellcode**. But what I don't get is,

 - Why is this associated to `kernel32.dll` which has nothing to do with the shellcode as of yet?
 -  Why is it already associated with our shellcode without us even having to **load this particular library/dll?**
 -  Why is it already associated without even having to **call any function from it previously**?

Well to answer that, let's take a step back and look at `three important dlls` in Windows that are crucial to the functioning of the Operating system by itself


1) **ntdll.dll**
2) **kernel32.dll**
3) **KERNELBASE.dll**

These dlls contain a lot of functions that are **crucial** to the very basic functioning of the Operating system itself and is constantly being accessed by **multiple** user **processes** and even windows internal processes to keep the operating system **functioning** and **alive**. Windows's own processes make use of various functions from these dlls to even start up the OS by itself. For example, The base services (like working with file systems, processes, devices, etc.) are provided by `kernel32.dll`. 

So I hope the importance of these dlls in the Windows operating system established now.

And because these dll's are **commonly used and loaded**, it would make a lot more sense to just **load them into the memory once** at system start and then pass `handles` (or) `pointers` as reference to other processes which require functions from these dlls. 

Which is exactly what happens and why it is already associated in a process's TEB->PEB by default.

And because these dlls are very important **they are by default imported by each and every thread/process** because it is required to even start up the thread in the first place. Especially `ntdll.dll` and `kernel32.dll`


To summarise, **we can find the kernel32.dll's base through the TEB associated with our shellcode thread because it is already imported when the OS runs the shellcode**.

So now we know where we can find these dll's being loaded and under what data structure can we find them. The how is explained in this series.

## - Compiling and running the shellcode

Loading the shellcode can be done by the help of a simple dropper program which carries our payload (shellcode) and runs it on the fly. This method is covered in my other blog post which you can find [here](https://tentative.link)


So now that we have the approach down
This is the final skeletal steps of our approach to write our shellcode

```
1) Get the kernel base address
2) Get the address to the Export table
3) Find the Base address of the WinExec function
4) Load the arguments into the WinExec function
5) Call the function
6) Compiling the shellcode
```

These 6 steps are going to be out outline for the writing the shellcode

We'll look into 64 bit shellcode in the next Part of this blog post.

