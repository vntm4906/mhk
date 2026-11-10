import base64
import json
import os
import re

from mhk_core import decrypt_bytes, keygen_from_params


def parse_int_list(text):
    """Đọc dãy số nguyên cách nhau bởi dấu phẩy, chấm phẩy hoặc khoảng trắng."""
    parts = [p for p in re.split(r"[,\s;]+", text.strip()) if p]
    return [int(p) for p in parts]


# khoá
def save_keys(folder, keys):
    """Ghi public.key (và private.key nếu có) vào thư mục. Trả về danh sách tệp đã ghi."""
    S, M = keys["public"]
    written = []
    path = os.path.join(folder, "public.key")
    with open(path, "w") as f:
        json.dump({"n": len(S), "S": S, "M": M}, f)
    written.append(path)
    if keys.get("private"):
        A, u, u_inv, M2 = keys["private"]
        path = os.path.join(folder, "private.key")
        with open(path, "w") as f:
            json.dump({"A": A, "u": u, "u_inv": u_inv, "M": M2}, f)
        written.append(path)
    return written


def load_key_file(path):
    """Đọc public.key hoặc private.key. private.key cho cả khoá công khai (tính lại S)."""
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if "A" in data:
        A = [int(x) for x in data["A"]]
        M, u, u_inv = int(data["M"]), int(data["u"]), int(data["u_inv"])
        k = keygen_from_params(A, M, u)            # kiểm tra lại các điều kiện
        if k["private"][2] != u_inv:
            raise ValueError("private.key không nhất quán: u^-1 không khớp u và M.")
        return k
    if "S" in data and "M" in data:
        return {"public": ([int(x) for x in data["S"]], int(data["M"])), "private": None}
    raise ValueError("Tệp khoá không đúng định dạng (không thấy trường A hoặc S).")


# bản mã
def cipher_width(M):
    return (M.bit_length() + 7) // 8


def pack_ciphertext(cts, length, M):
    w = cipher_width(M)
    blob = length.to_bytes(8, "big") + b"".join(c.to_bytes(w, "big") for c in cts)
    return base64.b64encode(blob).decode()


def unpack_ciphertext(text, M):
    try:
        blob = base64.b64decode("".join(text.split()), validate=True)
    except Exception:                                              # noqa: BLE001
        raise ValueError("Bản mã không phải chuỗi base64 hợp lệ.")
    if len(blob) < 8:
        raise ValueError("Bản mã quá ngắn.")
    length, body, w = int.from_bytes(blob[:8], "big"), blob[8:], cipher_width(M)
    if len(body) % w:
        raise ValueError("Độ dài bản mã không khớp với khoá (sai khoá hoặc bản mã bị hỏng).")
    cts = [int.from_bytes(body[i:i + w], "big") for i in range(0, len(body), w)]
    if any(c >= M for c in cts):
        raise ValueError("Bản mã chứa số lớn hơn hoặc bằng M (sai khoá hoặc bản mã bị hỏng).")
    return cts, length


def safe_decrypt(cts, length, private):
    """Giải mã có thông báo lỗi dễ hiểu."""
    n = len(private[0])
    if length > len(cts) * n // 8:
        raise ValueError("Độ dài gốc ghi trong bản mã không hợp lệ (sai khoá hoặc bản mã bị hỏng).")
    try:
        return decrypt_bytes(cts, private, length)
    except ValueError:
        raise ValueError("Giải mã thất bại: bản mã không hợp lệ với khoá riêng này (có thể sai khoá).")


# diễn giải từng bước
def trace_encrypt(bits, public):
    """Trả về (các dòng giải thích, C)."""
    S, M = public
    terms = [f"{b}*{s}" for b, s in zip(bits, S)]
    total = sum(b * s for b, s in zip(bits, S))
    C = total % M
    lines = [
        "Mã hoá: C = (Σ x_i * s_i) mod M",
        "  P = " + "".join(map(str, bits)),
        "  S = " + ", ".join(map(str, S)),
        "  C = (" + " + ".join(terms) + f") mod {M}",
        f"    = {total} mod {M}",
        f"    = {C}",
    ]
    return lines, C


def trace_decrypt(c, private):
    """Trả về (các dòng giải thích, bits)."""
    A, u, u_inv, M = private
    cp = (c * u_inv) % M
    lines = [
        "Giải mã: C' = C * u^-1 mod M, rồi giải ba lô siêu tăng với A'",
        f"  C' = {c} * {u_inv} mod {M} = {c * u_inv} mod {M} = {cp}",
        "  A' = " + ", ".join(map(str, A)),
    ]
    t, x = cp, [0] * len(A)
    for i in range(len(A) - 1, -1, -1):
        if t >= A[i]:
            lines.append(f"  C'={t} >= a'{i + 1}={A[i]}  ->  x{i + 1} = 1, C' := {t - A[i]}")
            x[i], t = 1, t - A[i]
        else:
            lines.append(f"  C'={t} <  a'{i + 1}={A[i]}  ->  x{i + 1} = 0")
    if t != 0:
        lines.append(f"  Còn dư {t} ≠ 0: bản mã KHÔNG hợp lệ với khoá này.")
        return lines, None
    lines.append("  P = " + "".join(map(str, x)))
    return lines, x
