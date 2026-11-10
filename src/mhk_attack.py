import time

from mhk_core import encrypt_block


class AttackCancelled(Exception):
    """Được ném ra khi người dùng bấm Dừng."""


def _check(should_stop):
    if should_stop is not None and should_stop():
        raise AttackCancelled()



# 1. Vét cạn
def brute_force(S, M, c, should_stop=None):
    """Thử toàn bộ 2^N tập con. Trả về danh sách các nghiệm (mỗi nghiệm là list bit)."""
    n = len(S)
    sums = [0]
    for i, s in enumerate(S):
        _check(should_stop)
        sums += [t + s for t in sums]          # chỉ số mask: bit i ứng với S[i]
    c %= M
    sols = []
    for mask, t in enumerate(sums):
        if t % M == c:
            sols.append([(mask >> i) & 1 for i in range(n)])
    return sols



# 2. Meet-in-the-middle

def _all_subset_sums(vals):
    sums = [0]
    for v in vals:
        sums += [t + v for t in sums]
    return sums


def meet_in_the_middle(S, M, c, should_stop=None):
    """Chia S làm hai nửa, lập bảng tổng nửa trái rồi tra nửa phải. Cỡ 2^(N/2)."""
    n = len(S)
    h = n // 2
    left, right = S[:h], S[h:]
    c %= M

    table = {}
    for mask, t in enumerate(_all_subset_sums(left)):
        table.setdefault(t % M, []).append(mask)
    _check(should_stop)

    sols = []
    for rmask, t in enumerate(_all_subset_sums(right)):
        if rmask & 0x3FFF == 0:
            _check(should_stop)
        for lmask in table.get((c - t) % M, ()):
            bits = [(lmask >> i) & 1 for i in range(len(left))]
            bits += [(rmask >> i) & 1 for i in range(len(right))]
            sols.append(bits)
    return sols



# 3. LLL (số nguyên, theo thuật toán tích phân của H. Cohen, mục 2.6.7)

def _dot(u, v):
    return sum(a * b for a, b in zip(u, v))


def lll_reduce(basis, delta=(99, 100), should_stop=None, progress=None):
    """Quy giản LLL một cơ sở nguyên (các hàng). Trả về cơ sở đã quy giản."""
    p, q = delta
    b = [None] + [list(r) for r in basis]      # đánh chỉ số từ 1
    n = len(basis)
    d = [0] * (n + 1)
    lam = [[0] * (n + 1) for _ in range(n + 1)]
    d[0] = 1
    d[1] = _dot(b[1], b[1])

    def red(k, l):
        if 2 * abs(lam[k][l]) > d[l]:
            qq = (2 * lam[k][l] + d[l]) // (2 * d[l])      # làm tròn gần nhất
            b[k] = [x - qq * y for x, y in zip(b[k], b[l])]
            lam[k][l] -= qq * d[l]
            for i in range(1, l):
                lam[k][i] -= qq * lam[l][i]

    def swap(k, kmax):
        b[k], b[k - 1] = b[k - 1], b[k]
        for j in range(1, k - 1):
            lam[k][j], lam[k - 1][j] = lam[k - 1][j], lam[k][j]
        l_ = lam[k][k - 1]
        B = (d[k - 2] * d[k] + l_ * l_) // d[k - 1]
        for i in range(k + 1, kmax + 1):
            t = lam[i][k]
            lam[i][k] = (d[k] * lam[i][k - 1] - l_ * t) // d[k - 1]
            lam[i][k - 1] = (B * t + l_ * lam[i][k]) // d[k]
        d[k - 1] = B

    k, kmax, steps = 2, 1, 0
    while k <= n:
        if k > kmax:
            kmax = k
            for j in range(1, k + 1):
                u = _dot(b[k], b[j])
                for i in range(1, j):
                    u = (d[i] * u - lam[k][i] * lam[j][i]) // d[i - 1]
                if j < k:
                    lam[k][j] = u
                else:
                    d[k] = u
            if d[k] == 0:
                raise ValueError("Cơ sở phụ thuộc tuyến tính")
        red(k, k - 1)
        # điều kiện Lovasz: q*d[k]*d[k-2] < p*d[k-1]^2 - q*lam^2
        if q * d[k] * d[k - 2] < p * d[k - 1] ** 2 - q * lam[k][k - 1] ** 2:
            swap(k, kmax)
            k = max(2, k - 1)
        else:
            for l in range(k - 2, 0, -1):
                red(k, l)
            k += 1
        steps += 1
        if steps & 0x1FF == 0:
            _check(should_stop)
            if progress:
                progress(steps, k, n)
    return b[1:]


def _lll_once(S, M, c, K, delta, should_stop, progress):
    """Một lần tấn công dàn với hệ số tỉ lệ K và tham số delta cho trước."""
    n = len(S)
    basis = []
    for i in range(n):
        row = [0] * (n + 2)
        row[i] = 2
        row[n] = K * S[i]
        basis.append(row)
    basis.append([0] * n + [K * M, 0])
    basis.append([1] * n + [K * c, 1])

    red = lll_reduce(basis, delta=delta, should_stop=should_stop, progress=progress)
    for v in red:
        if v[n] != 0 or abs(v[n + 1]) != 1:
            continue
        if any(abs(x) != 1 for x in v[:n]):
            continue
        sign = -v[n + 1]                       # đưa toạ độ cuối về -1
        bits = [(sign * x + 1) // 2 for x in v[:n]]
        if encrypt_block(bits, (S, M)) == c:
            return bits
    return None


def lll_attack(S, M, c, should_stop=None, progress=None, max_attempts=8):
    """Tấn công quy giản dàn theo kiểu CJLOSS (Lagarias-Odlyzko cải tiến).

    Dựng dàn gồm n+2 hàng:
        b_i = (2*e_i,  K*S[i], 0)     i = 1..n
        b_M = (0...0,  K*M,    0)
        b_t = (1...1,  K*C,    1)
    Với x đúng và k đúng: sum(x_i*b_i) - b_t + k*b_M = (2x_i-1, 0, -1),
    một vectơ rất ngắn (các toạ độ chỉ là +-1 hoặc 0). LLL thường tìm ra nó,
    nhưng KHÔNG đảm bảo: tấn công mang tính xác suất, nên thử lại với thứ tự
    cột và hệ số K khác nhau.

    Trả về (nghiệm hoặc None, thông tin phụ). Nghiệm luôn được kiểm lại bằng cách mã hoá.
    """
    import random
    n = len(S)
    c %= M
    rng = random.Random(12345)                 # cố định hạt giống để kết quả lặp lại được
    k_choices = [n + 1, 2 * n, max(2, n // 2), 4 * n]
    deltas = [(99, 100), (999, 1000)]
    for attempt in range(max_attempts):
        _check(should_stop)
        perm = list(range(n))
        if attempt > 0:
            rng.shuffle(perm)                  # đổi thứ tự cột
        S2 = [S[i] for i in perm]
        K = k_choices[attempt % len(k_choices)]
        delta = deltas[(attempt // 2) % len(deltas)] if attempt else deltas[0]
        bits2 = _lll_once(S2, M, c, K, delta, should_stop, progress)
        if bits2 is not None:
            bits = [0] * n
            for pos, orig_idx in enumerate(perm):
                bits[orig_idx] = bits2[pos]
            if encrypt_block(bits, (S, M)) == c:
                return bits, {"dim": n + 2, "attempts": attempt + 1}
    return None, {"dim": n + 2, "attempts": max_attempts}


# Tiện ích dùng chung cho CLI/GUI
# ---------------------------------------------------------------------------
METHODS = {
    "brute": ("Vét cạn", brute_force, 22),
    "mitm": ("Meet-in-the-middle", meet_in_the_middle, 44),
    "lll": ("Quy giản dàn LLL", None, None),   # không giới hạn cứng; tấn công mang tính xác suất
}


def run_method(key, S, M, c, should_stop=None, progress=None):
    """Chạy một phương pháp, trả về (list_nghiệm, giây)."""
    t0 = time.perf_counter()
    if key == "brute":
        sols = brute_force(S, M, c, should_stop)
    elif key == "mitm":
        sols = meet_in_the_middle(S, M, c, should_stop)
    elif key == "lll":
        sol, _ = lll_attack(S, M, c, should_stop, progress)
        sols = [sol] if sol is not None else []
    else:
        raise ValueError("Phương pháp không hợp lệ")
    return sols, time.perf_counter() - t0


def density(S):
    """Mật độ của ba lô: N / log2(max S). Mật độ thấp thì tấn công dàn hiệu quả."""
    import math
    return len(S) / math.log2(max(S))


def crack_blocks(S, M, cts, method="lll", should_stop=None):
    """Tấn công lần lượt từng khối bản mã, CHỈ dùng khoá công khai (S, M).

    Sinh ra (chỉ số khối, bits tìm được hoặc None, số nghiệm, số giây) cho từng khối,
    để giao diện hiển thị tiến độ. Nếu có nhiều nghiệm, lấy nghiệm đầu tiên và báo số nghiệm.
    """
    for i, c in enumerate(cts):
        sols, secs = run_method(method, S, M, c, should_stop)
        yield i, (sols[0] if sols else None), len(sols), secs
