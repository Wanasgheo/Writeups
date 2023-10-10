# Array of Sunshine
This is the easiest challenge of the CTF which simply let us to write something in an array position
Here is the main function that is loop called
```c
void basket(void){
  int index;
  // Fruit from the BSS
  
  printf("\nWhich fruit would you like to eat [0-3] >>> ");
  scanf("%d", &index);
  printf("Replace it with a new fruit.\n",*(char *)(fruits + (long)index * 8));
  printf("Type of new fruit >>>");
  // No Boundary checks
  scanf("%24s",fruits + (long)index * 8);
  exit(-1);
}
```
As you can see there is no boundary check so we cna just insert which index we want and write an arbitrary value in so it si basically a write-what-where challenge

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/7dce6369-0ee8-43d0-b4d8-57c4a8679e1c)

This is the bss where we can write we have some functions before but if we look before the array there is something interesting

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/771efb62-8b78-4fc3-b0d5-e0e5c6e8ff0f)

There is the `exit()`'s got entry which is located at `-8`, so we can just overwrite it with the `win()` function

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/c11152b2-d615-4216-aba1-03d548cf21ff)

We successfully overwrote the entry and thats the flag

![image](https://github.com/Wanasgheo/Writeups/assets/111740362/8a6ac05f-fe3c-442e-a15c-fd8a66acf1e2)
