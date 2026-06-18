import random

def init(seed):
    random.seed(seed)

def fuzz(buf, add_buf, max_size):
    data = bytearray(buf)
 
    # Make sure there's room for the 8-byte structure we want to impose.
    if len(data) < 8:
        data.extend(b"\x00" * (8 - len(data)))
    if len(data) > max_size:
        data = data[:max_size]
    if len(data) < 8:
        return data  # can't fit the structure; hand it back unchanged
 
    # Initial Random Havoc
    for _ in range(4):
        pos = random.randrange(len(data))
        data[pos] ^= random.randint(0, 255)
 
    # 95% of the time, satisfy the "FUZZ" magic gate.
    if random.randint(0, 99) < 95:
        data[0:4] = b"FUZZ"
 
    # 30% of the time, aim byte 4 at the overflow / OOB-read paths.
    if random.randint(0, 99) < 50:
        data[4] = 0x41
    else:
        data[4] = random.randint(0, 255)
 
    # 10% of the time, line up the deeper "BOM" command path.
    if random.randint(0, 99) < 10:
        data[5:8] = b"BOM"
 
    return data

def deinit():
    pass