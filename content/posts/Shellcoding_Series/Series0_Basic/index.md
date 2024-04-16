---
title: Windows Shellcoding Series 0
date: 2024-03-27
author: retr0ds
author_url: https://twitter.com/_retr0ds_
categories:
  - Reversing
tags:
  - Blog
  - Shellcode
  - Windows
  
series: ["Shellcoding"]
series_order: 1
---


# Windows Shellcoding Series 0


## Init()
Welcome to the prequel blogpost of my Shellcoding Series
With this I intend to start of a series of Shellcoding based blogposts aiming to develop and post interesting shellcodes

The pre-requisite to follow this series of blog posts:

- A laptop ofc
- Bad social life (Why else would you be on here?)
- An omnitirix (Everyone has one these days)
- The Hardcover **Windows internals book by Pavel Yosifovich 7th edition** (to place your laptop on for good ergonomics)

## The Why?

![image](https://hackmd.io/_uploads/HyhaaubJR.png)

I have always been fascinated by shellcode (especially in windows) and the intricacies it holds.

Striving to create a nulbyte free shellcode, limiting the shellcode to under a certain size are some of the intricacies that we'll get into as well

The idea of being able to use a set of bytes as a payload to inject into memory and to execute it has always seemed fun to me.

So I thought the best way to learn shellcoding is to make a blog series out of it as I experiment my way through shellcode and windows internals . And I hope to learn a lot out of this journey while being able to share to the community as well.


Well, without further ado, let's jump right into the topic!


## What is Shellcode?

![image](https://hackmd.io/_uploads/ryR0-9Z1A.png)


Simply put, a piece of shellcode is a set of bytes(of assembly instructions) that can be loaded in memory and executed like any other piece of assembly code.

A shellcode is a versatile piece of code that allows us to dynamically load a block of assembly instructions and execute it on the fly thereby enhancing the capabilities of a binary. It is particularly useful for malicious purposes, when combined with an encrypter or a packer it can go  undetected under various EDRs and other AV scanners and checkers.

**For example**

```c
char shellcode[] = "\x90\x90\xcc\xc3"
```

\x90 is for NOP
\xcc is for INT3
\xc3 is for RET

This payload/shellode translates to 

```wasm!
NOP
NOP
INT3
RET
```

And this shellcode can be loaded into memory and executed like any other section of assembly code

We'll be covering the loading of shellcode in the other blogposts of mine

## What does it accomplish?

Now clearly the above shown shellcode doesn't accomplish much

There's much more powerful and useful shellcode harboring malicious intent such as connecting to a c2 server and downloading the actual malicious file, dll injection, processs injection and many more.

There's a pretty neat interface to get working shellcode for this purpose on windows

### MsfVenom

![image](https://hackmd.io/_uploads/S1bMtF-1R.png)


MsfVenom is a shellcode generator that has templates based upon which we can customize our own payload
 
Now this series doesn't cover shellcode generation by MsfVenom, Metasploit has a pretty neat [documentation](https://docs.metasploit.com/docs/using-metasploit/basics/how-to-use-msfvenom.html) for that. Feel free to check that out.

![image](https://hackmd.io/_uploads/HkzLW9-y0.png)



## About this series

Now this series aims to showcase various shellcode/payload for various purposes on windows and aims to completely write it from scratch and in the process also learn a lot about Windows Internals, it's structures, APIs and techniques

This series would mostly look like a walkthrough rather than a research blog, because it is being written as I am exploring around in windows internals and red teaming as well.



## Exit()

With all that being said, now let's get down to business and let's write some basic windows shellcode begining with the next blog post. 