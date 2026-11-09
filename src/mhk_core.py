import secrets
from math import gcd 

def egcd(a, b):
  """Euclid mở rộng (bản lặp). Trả về (g, x, y) sao cho a*x + b*y = g."""
  x0, y0, x1, y1 = 1, 0, 0, 1
  while b:
    q = a // b
    a, b = b, a - q * b
    x0, x1 = x1, x0 - q * x1
    y0, y1 = y1, y0 - q * y1
  return a, x0, y0 

def mod_inverse(u, m):
  g, x, _ = egcd(u,m)
  if g != 1:
      raise ValueError("u và M phải nguyên tố cùng nhau")
  return x % m 

def is_super_increasing(a): 
    s = 0
    for v in a: 
        if v <= s:
            return False 
        s += v 
    return True

def keygen from params(A, M, u):
    """Sinh khoá từ tham số cho trước (dùng cho ví dụ tính tay)."""
    if not is_super_increasing(A):
        raise ValueError("A' không phải dãy siêu tăng") 
    if M <= sum(A):
        raise ValueError("Cần M > tổng các phần tử của A'")
    if gcd(u, M) != 1: 
        raise ValueError("Cần gcd(u, M) = 1")
    S = [(a * u) % M for a in A]
    u_inv = mod_inverse(u, M) 
    return {"public": (S,M), "private": (A, u, u_inv, M)}

def keygen_random(n): 
    """Sinh khoá ngẫu nhiên cho khối n bit (dùng secrets, không dùng random)."""
    A, s = [], 0
    for _ in range(n): 
        a = s + 1 + secrets.randbelow(2 ** n)
        A.append(a)
        s += a 
    M = 2 * A[-1] + 1 + secrets.randbelow(2 ** n)     # thoả M > 2*a'_n
    while True:
        u = 2 + secrets.randbelow(M - 3) 
        if gcd(u, M) == 1: 
            break
    return keygen_from_params(A, M, u)

def encrypt_block(bits, public):
    S, M = public
    if len(bits) != len(S):
        raise ValueError("Độ dài khối khác N")
    if any(b not in (0, 1) for b in bits):
        raise ValueError("Mỗi bit của bản rõ phải là 0 hoặc 1")
    return sum(s for s, b in zip(S, bits) if b) % M


def solve_super_increasing(A, target):
    """Giải ba lô 0/1 siêu tăng. So sánh với target (C), KHÔNG phải M."""
    x = [0] * len(A)
    for i in range(len(A) - 1, -1, -1):
        if target >= A[i]:
            x[i] = 1
            target -= A[i]
    return x if target == 0 else None

def decrypt_block(c, private):
    A, u, u_inv, M = private
    x = solve_super_increasing(A, (c * u_inv) % M)
    if x is None:
        raise ValueError("Bản mã không hợp lệ")
    return x

# ---------- xử lý dữ liệu thật (byte) ----------
def bytes_to_bits(data):
    return [(byte >> (7 - i)) & 1 for byte in data for i in range(8)]   # MSB trước

def bits_to_bytes(bits):
    out = bytearray()
    for i in range(0, len(bits), 8):
        v = 0
        for b in bits[i:i + 8]:
            v = (v << 1) | b
        out.append(v)
    return bytes(out)

def encrypt_bytes(data, public):
    n = len(public[0])
    bits = bytes_to_bits(data)
    bits += [0] * (-len(bits) % n)                 # đệm 0 cho đủ khối
    cts = [encrypt_block(bits[i:i + n], public) for i in range(0, len(bits), n)]
    return cts, len(data)                          # lưu độ dài gốc để bỏ phần đệm

def decrypt_bytes(cts, private, length):
    bits = []
    for c in cts:
        bits += decrypt_block(c, private)
    return bits_to_bytes(bits)[:length]
