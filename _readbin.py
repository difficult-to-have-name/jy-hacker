def int2hex(int_list: list[int]):
    return [f"0x{x:02x}" for x in int_list]


def multi_print(data: bytes):
    print(byte_data.hex(" "))
    print(int2hex(list(byte_data)))
    print(len(byte_data))


# with open('.\\assets\\shutdown.bin', 'rb') as f:
#     print("shutdown.bin:")
#     byte_data = f.read()
#     multi_print(byte_data)

# with open('.\\assets\\restart.bin', 'rb') as f:
#     print("restart.bin:")
#     byte_data = f.read()
#     multi_print(byte_data)

# with open('.\\assets\\msg.bin', 'rb') as f:
#     print("msg.bin:")
#     byte_data = f.read()
#     multi_print(byte_data)

with open('.\\assets\\cmd.bin', 'rb') as f:
    print("cmd.bin:")
    byte_data = f.read()
    multi_print(byte_data)
