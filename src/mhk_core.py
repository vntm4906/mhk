def encrypt block(bits, public):
    S, M = public
    if len(bits) != len(S):
        raise ValueError("Độ dài khối khác N")
    if any(b not in (0, 1) for b in bits):
        raise ValueError("Mỗi bit của bản rõ phải là 0 hoặc 1")
    return sum(s for s, b in zip(S, bits) if b) % M

def solve super increasing(A, target):
    """Giải ba lô 0/1 siêu tăng. So sánh với target (C), KHÔNG phải M."""
    x = [0] * len(A)
    for i in range(len(A) - 1, -1, -1):
        if target >= A[i]:
            x[i] = 1
            target -= A[i]
    return x if target == 0 else None

def decrypt block(c, private):
    A, u, u inv, M = private
    x = solve super increasing(A, (c * u inv) % M
    if x is None:
        raise ValueError("Bản mã không hợp lệ")
    return x

# ---------- xử lý dữ liệu thật (byte) ----------
def bytes_to_bits(data):
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]   #
MSB trước

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)

def encrypt bytes(data, public):
    n = len(public[0])
    bits = bytes_to_bits(data)
    bits += [0] * (-len(bits) % n)                 # đệm 0 cho đủ khối
    cts = [encrypt block(bits[i:i + n], public) for i in range(0, len(bits), n)]
    return cts, len(data)                          # lưu độ dài gốc để bỏ phần đệm 

def decrypt bytes(cts, private, length):
    bits = []
    for c in cts:
        bits += decrypt block(c, private)
    return bits_to_bytes(bits)[:length]
      
