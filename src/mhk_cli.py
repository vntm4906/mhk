import hashlib        # CHỈ dùng để đối chiếu toàn vẹn, không thuộc phần lõi mật mã 
import os
import secrets 
import sys
import textwrap 
import time 
from math import gcd

from mhk_core import (decrypt_block, encrypt_block, encrypt_bytes, is_super_increasing, keygen_from_params, keygen_random)
from mhk_io import (cipher_width, load_key_file, pack_ciphertext, parse_int_list, safe_decrypt, save_keys, trace_decrypt, trace_encrypt, unback_ciphertext)
import importlib.util

# Phần tấn công là tuỳ chọn; kiểm tra có tệp mà không import ngay (tránh vòng lặp import).
HAS_ATTACK = all(importlib.util.find_spec(m) is not None for m in ("mhk_attack", "mhk_attack_cli"))

FILE_WARN = 1 * 1024 * 1024
FILE_MAX = 5 * 1024 *  1024
LINE = "=" * 64
THIN = "=" * 64

def setup_console():
    """Dùng UTF-8 khi đầu vào/ra không phải màn hình console (ví dụ chuyển hướng tệp)."""
    for stream in (sys.stdin, sys.stdout, sys.stderr):
        try:
             if not stream.isatty(): 
                 stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:                                             # noga: BLE001
            pass

def ask(prompt, default=None): 
    suffix = f" [{default}]" if default not in (None, "") else "" 
    s = input(f"{prompt}{suffix}: ").strip()
    return s if s else (default if default is not None else "")

def ask_path(prompt, default=None):
    """Đọc đường dẫn; tự bỏ dấu nháy (khi kéo thả tệp vào cmd, Windows thêm dấu nháy)."""
    return ask(prompt, default).strip('"').strip("'")

def ask_int(prompt, default, lo, hi):
    while True: 
        s = ask(prompt, str(default))
        try:
            v = int(s)
            if lo <= v <= hi:
                return v
        except ValueError:
            pass
        print(f"  ! Hãy nhập số nguyên từ {lo} đến {hi}.")

def confirm(prompt, default=False):
    d = "c" if default else "k" 
    s = ask(f"{prompt} (c = có, k = không)", d).lower()
  return s in ("c", "co", "có", "y", "yes")

def pause():
    input("\nNhấn Enter để quay lại menu...")

def err(msg): 
    print(f"  ! {msg}")

def wrap(label, items): 
    print(textwrap.fill(f"{label} = {', '.join(map(str, items))}", width=78, subsequent_indent="

class State: 
    def __init__(self)
        self.keys = None         # {"public": (S,M), "private": (A,u,u_inv,M) | None}

def need_public(st): 
    if st.keys is None: 
        err("Chứa có khoá. Hãy dùng mục 1, 2, 3 hoặc 6 trước.")
        return None
    return st.keys["public"]

def need_private(st):
    if st.keys is None: 
        err("Chưa có khoá. Hãy dùng mục 1, 2, 3 hoặc 6 trước.")
        return None 
    if not st.keys["private"]:
        err("Khoá hiện tại chỉ có phần công khai nên không giải mã được. Hãy nạp private.key (mục 6).")
        return None
    return st.keys["private"]

def status_line(st):
    if st.keys is None: 
        return "Khoá hiện tại:  (chưa có)"
    S, M = st.keys["public"]
    quyen = "mã hoá + giải mã" if st.keys["private"] else "CHỈ mã hoá"
    return f"Khoá hiện tại: N = {len(S), M có {M.bit_length() bit | {quyen}" 

def show_key(st):
    if st.keys is None: 
        err("Chưa có khoá.")
        return
    S, M = st.keys["public"] 
    print(THIN)
    print(f"N = {len(S)]")
    print(f"M = {M}") 
    wrap("S (khoá công khai)", S)
    if st.keys["private"]: 
        A, u, u_inv, _ = st.keys["private"] 
        wrap("A' (khoá riêng)", A) 
        print(f"u = {u}")
        print(f"u^-1 = {u_inv}") 
        print("Kiểm tra điều kiện:")
        print(f" A' siêu tăng      : {'đạt' if is_super_increasing(A) else 'KHÔNG ĐẠT'}")
        print(f" M > tổng A'       : {'đạt' if M > sum(A) else 'KHÔNG đạt'} ({M} so với {sum(A)})
        print(f" gcd(u, M) = 1     : {'đạt' if gcd(u, M) == 1 else 'KHÔNG đạt'}")
        print(f" u * u^-1 mod M    : {(u * u_inv) % M} (phải bằng 1)")
    else:
        print("(Chỉ có khoá công khai: mã hoá được, KHÔNG giải mã được.)")
    print(THIN) 

    def act_keygen_random(st):
        n = ask_int("Số bit mỗi khối N", 64, 4, 256)
        st.keys = keygen_random(n)
        print(f"Đã sinh khoá ngẫu nhiên với N = {n}.")
        show_key(st)

    def act_keygen_manual(st):
        print("Nhập tham số. Ví dụ BTVD2: A' = 2,3,6,12,25   M = 53   u = 46")
        try:
            A = parse_int_list(ask("A' (các số cách nhau bởi dấu phẩy)"))
            M = int(ask("M"))
            u = int(ask("u"))
            st.keys = keygen_from_params(A, M, u)
        except ValueError as exc:
            err(f"Không sinh được khoá: {exc}")
            err("Kiểm tra: A' siêu tăng, M > tổng A', gcd(u, M) = 1, và mọi ô là số nguyên.")
            return
        show_key(st)

def act_example(st):
    st.keys = keygen_from_params([2, 3, 6, 12, 25], 53, 46)
    print("Đã nạp ví dụ BTVD2: A' = (2,3,6,12,25), M = 53, u = 46.")
    show_key(st)

def act_save(st):
    if st.keys is None:
        err("Chưa có khoá để lưu.")
        return
    folder = ask_path("Thư mục lưu khoá", ".")
    if not os.path.isdir(folder):
        err("Thư mục không tồn tại.")
        return
    existing = [n for n in ("public.key", "private.key") if os.path.exists(os.path.join(folder, n))]
    if existing and not confirm(f"Đã có {', '.join(existing)}. Ghi đè sẽ làm mất khoá cũ. Tiếp tục?"):
        print("Đã huỷ.")
        return
    try:
        written = save_keys(folder, st.keys)
    except OSError as exc:
        err(f"Lỗi ghi tệp: {exc}")
        return
    for p in written:
        print(f"Đã ghi: {p}")
    print("Lưu ý: private.key là văn bản thuần, không đưa lên GitHub.")

def act_load(st, path=None):
    path = path or ask_path("Đường dẫn tệp public.key hoặc private.key", "private.key")
    try:
        st.keys = load_key_file(path)
    except FileNotFoundError:
        err(f"Không tìm thấy tệp: {path}")
        return
    except Exception as exc:                                       # noqa: BLE001
        err(f"Không nạp được khoá: {exc}")
        return
    print(f"Đã nạp khoá từ {path}.")
    show_key(st)  

# ----------------------------------------------------------------- khối nhỏ
def act_block(st):
    public = need_public(st)
    if public is None:
        return
    n = len(public[0])
    print(f"Chế độ từng bước, mỗi lần một khối N = {n} bit.")
    print("  1. Mã hoá một khối     2. Giải mã một khối     3. Mã hoá rồi giải mã")
    mode = ask("Chọn", "3")
    if mode not in ("1", "2", "3"):
        err("Lựa chọn không hợp lệ.")
        return
    C = None
    if mode in ("1", "3"):
        s = ask(f"Bản rõ P ({n} ký tự 0/1)")
        if len(s) != n or set(s) - {"0", "1"}:
            err(f"Phải nhập đúng {n} ký tự gồm 0 và 1.")
            return
        lines, C = trace_encrypt([int(ch) for ch in s], public)
        print("\n".join(lines))
    if mode in ("2", "3"):
        private = need_private(st)
        if private is None:
            return
        if C is None:
            try:
                C = int(ask("Bản mã C (số nguyên)"))
            except ValueError:
                err("C phải là số nguyên.")
                return
        if not 0 <= C < private[3]:
            err(f"C phải thoả 0 <= C < M = {private[3]}.")
            return
        if mode == "3":
            print()
        lines, _ = trace_decrypt(C, private)
        print("\n".join(lines))

# ----------------------------------------------------------------- văn bản
def read_multiline():
    print("Nhập văn bản (kết thúc bằng một dòng trống):")
    lines = []
    while True:
        try:
            line = input()
        except EOFError:
            break
        if line == "":
            break
        lines.append(line)
    return "\n".join(lines)

def act_text_encrypt(st):
    public = need_public(st)
    if public is None:
        return
    text = read_multiline()
    data = text.encode("utf-8")
    if not data:
        err("Chưa nhập gì.")
        return
    if len(data) > 200_000:
        err("Văn bản quá dài (trên 200 000 byte). Hãy dùng mục mã hoá tệp.")
        return
    t0 = time.perf_counter()
    cts, length = encrypt_bytes(data, public)
    secs = time.perf_counter() - t0
    packed = pack_ciphertext(cts, length, public[1])
    raw = 8 + len(cts) * cipher_width(public[1])
    print(THIN)
    print("Bản mã (base64):")
    print(packed)
    print(THIN)
    print(f"{length} byte -> {len(cts)} khối, {secs:.4f} giây; bản mã thô {raw} byte "
          f"(gấp {raw / length:.2f} lần bản rõ).")
    out = ask_path("Lưu bản mã vào tệp (Enter để bỏ qua)")
    if out:
        write_text_file(out, packed) 

def write_text_file(path, content):
    if os.path.exists(path) and not confirm(f"Tệp {path} đã tồn tại. Ghi đè?"):
        print("Đã huỷ ghi tệp.")
        return
    try:
        with open(path, "w") as f:
            f.write(content)
        print(f"Đã ghi: {path}")
    except OSError as exc:
        err(f"Lỗi ghi tệp: {exc}")


def act_text_decrypt(st):
    private = need_private(st)
    if private is None:
        return
    s = ask_path("Dán bản mã base64, hoặc gõ @đường_dẫn_tệp để đọc từ tệp")
    if s.startswith("@"):
        try:
            with open(s[1:].strip('"'), encoding="ascii") as f:
                s = f.read()
        except (OSError, UnicodeDecodeError) as exc:
            err(f"Không đọc được tệp: {exc}")
            return
    try:
        cts, length = unpack_ciphertext(s, private[3])
        t0 = time.perf_counter()
        plain = safe_decrypt(cts, length, private)
        secs = time.perf_counter() - t0
    except ValueError as exc:
        err(str(exc))
        return
    text = plain.decode("utf-8", errors="replace")
    print(THIN)
    print("Bản rõ sau giải mã:")
    print(text)
    print(THIN)
    note = " (có byte không phải UTF-8 hợp lệ, đã thay bằng �)" if "\ufffd" in text else ""
    print(f"Đã giải mã {length} byte trong {secs:.4f} giây.{note}")

# ----------------------------------------------------------------- tệp
def check_input_file(path, limit=True):
    if not path or not os.path.isfile(path):
        err("Không tìm thấy tệp đầu vào.")
        return False
    size = os.path.getsize(path)
    if limit and size > FILE_MAX:
        err(f"Tệp {size / 1024 / 1024:.1f} MB vượt giới hạn {FILE_MAX // (1024 * 1024)} MB "
            "(cài đặt Python thuần tốn nhiều bộ nhớ).")
        return False
    if limit and size > FILE_WARN and not confirm(f"Tệp {size / 1024 / 1024:.1f} MB, có thể mất vài giây. Tiếp tục?", True):
        return False
    return True


def act_file_encrypt(st):
    public = need_public(st)
    if public is None:
        return
    path = ask_path("Tệp cần mã hoá")
    if not check_input_file(path):
        return
    out = ask_path("Lưu bản mã vào", path + ".mhk")
    if os.path.exists(out) and not confirm(f"Tệp {out} đã tồn tại. Ghi đè?"):
        print("Đã huỷ.")
        return
    try:
        with open(path, "rb") as f:
            data = f.read()
        print("Đang mã hoá...")
        t0 = time.perf_counter()
        cts, length = encrypt_bytes(data, public)
        secs = time.perf_counter() - t0
        with open(out, "w") as f:
            f.write(pack_ciphertext(cts, length, public[1]))
    except OSError as exc:
        err(f"Lỗi đọc/ghi tệp: {exc}")
        return
    raw = 8 + len(cts) * cipher_width(public[1])
    print(f"Xong: {length} byte -> {len(cts)} khối, {secs:.3f} giây.")
    print(f"Bản mã thô {raw} byte (gấp {raw / max(length, 1):.2f} lần); tệp ghi {os.path.getsize(out)} byte (base64).")
    print(f"Đã ghi: {out}")

def act_file_decrypt(st):
    private = need_private(st)
    if private is None:
        return
    path = ask_path("Tệp bản mã cần giải mã")
    if not check_input_file(path, limit=False):
        return
    default_out = path[:-4] if path.endswith(".mhk") else path + ".giaima"
    out = ask_path("Lưu tệp sau giải mã vào", default_out)
    if os.path.exists(out) and not confirm(f"Tệp {out} đã tồn tại. Ghi đè?"):
        print("Đã huỷ.")
        return
    try:
        with open(path, encoding="ascii") as f:
            text = f.read()
    except UnicodeDecodeError:
        err("Tệp này không phải bản mã base64 (chứa ký tự ngoài ASCII).")
        return
    except OSError as exc:
        err(f"Lỗi đọc tệp: {exc}")
        return
    try:
        cts, length = unpack_ciphertext(text, private[3])
        print("Đang giải mã...")
        t0 = time.perf_counter()
        plain = safe_decrypt(cts, length, private)
        secs = time.perf_counter() - t0
        with open(out, "wb") as f:
            f.write(plain)
    except ValueError as exc:
        err(str(exc))
        return
    except OSError as exc:
        err(f"Lỗi ghi tệp: {exc}")
        return
    print(f"Xong: {length} byte, {len(cts)} khối, {secs:.3f} giây.")
    print(f"Đã ghi: {out}")

def act_file_check(st):
    public = need_public(st)
    private = need_private(st) if public else None
    if private is None:
        return
    path = ask_path("Tệp cần kiểm tra vòng (mã hoá rồi giải mã, không ghi tệp)")
    if not check_input_file(path):
        return
    try:
        with open(path, "rb") as f:
            data = f.read()
    except OSError as exc:
        err(f"Lỗi đọc tệp: {exc}")
        return
    print("Đang xử lý...")
    t0 = time.perf_counter()
    cts, length = encrypt_bytes(data, public)
    t1 = time.perf_counter()
    plain = safe_decrypt(cts, length, private)
    t2 = time.perf_counter()
    # hashlib chỉ để đối chiếu hai bản, không phải phần lõi mật mã
    ok = hashlib.sha256(data).hexdigest() == hashlib.sha256(plain).hexdigest()
    print(f"{length} byte, {len(cts)} khối | mã hoá {t1 - t0:.3f} s | giải mã {t2 - t1:.3f} s")
    print(f"SHA-256 trước và sau giải mã: {'TRÙNG KHỚP' if ok else 'KHÁC NHAU (có lỗi)'}")


# ----------------------------------------------------------------- tấn công
def act_attack(st):
    """Mở menu tấn công (mhk_attack_cli.py); truyền khoá công khai hiện tại nếu có."""
    if not HAS_ATTACK:
        err("Thiếu mhk_attack.py hoặc mhk_attack_cli.py trong cùng thư mục nên không dùng được mục này.")
        return
    from mhk_attack_cli import attack_menu        # import muộn để tránh vòng lặp import
    attack_menu(st.keys["public"] if st.keys else None, back_label="Quay lại menu chính")

# ----------------------------------------------------------------- đo thời gian
def act_benchmark(st):
    public = need_public(st)
    private = need_private(st) if public else None
    if private is None:
        return
    print(f"Đo thời gian với khoá hiện tại (N = {len(public[0])}), dữ liệu ngẫu nhiên.")
    print(f"{'Kích thước':>12} | {'Mã hoá (s)':>11} | {'Giải mã (s)':>11} | {'Số khối':>8}")
    for size in (1_000, 10_000, 100_000, 500_000):
        data = secrets.token_bytes(size)
        t0 = time.perf_counter()
        cts, length = encrypt_bytes(data, public)
        t1 = time.perf_counter()
        plain = safe_decrypt(cts, length, private)
        t2 = time.perf_counter()
        flag = "" if plain == data else "  <-- LỖI"
        print(f"{size:>10} B | {t1 - t0:>11.4f} | {t2 - t1:>11.4f} | {len(cts):>8}{flag}")
    print("Thời gian phụ thuộc máy; hãy đo lại trên máy trình chiếu.")


# ----------------------------------------------------------------- menu
MENU = [
    ("KHOÁ", None),
    ("1", ("Sinh khoá ngẫu nhiên", act_keygen_random)),
    ("2", ("Nhập tham số thủ công (A', M, u)", act_keygen_manual)),
    ("3", ("Nạp ví dụ BTVD2 (A'=2,3,6,12,25; M=53; u=46)", act_example)),
    ("4", ("Xem khoá hiện tại", lambda st: show_key(st))),
    ("5", ("Lưu khoá ra tệp (public.key, private.key)", act_save)),
    ("6", ("Nạp khoá từ tệp", lambda st: act_load(st))),
    ("MÃ HOÁ / GIẢI MÃ", None),
    ("7", ("Một khối, hiện từng bước tính (minh hoạ ví dụ tay)", act_block)),
    ("8", ("Mã hoá văn bản", act_text_encrypt)),
    ("9", ("Giải mã văn bản", act_text_decrypt)),
    ("10", ("Mã hoá tệp", act_file_encrypt)),
    ("11", ("Giải mã tệp", act_file_decrypt)),
    ("12", ("Kiểm tra vòng một tệp (SHA-256, không ghi tệp)", act_file_check)),
    ("PHÂN TÍCH", None),
    ("13", ("Menu tấn công (vét cạn / meet-in-the-middle / LLL / phá tệp bản mã)", act_attack)),
    ("14", ("Đo thời gian theo kích thước dữ liệu", act_benchmark)),
]

def print_menu(st):
    print()
    print(LINE)
    print("   HỆ MÃ BA LÔ MERKLE-HELLMAN (MHK) - GIAO DIỆN DÒNG LỆNH")
    print(LINE)
    print(status_line(st))
    print(THIN)
    for key, item in MENU:
        if item is None:
            print(f" [{key}]")
        else:
            label, _ = item
            if key == "13" and not HAS_ATTACK:
                label += "  (thiếu mhk_attack.py / mhk_attack_cli.py)"
            print(f"  {key:>2}. {label}")
    print("   0. Thoát")
    print(THIN)

def maybe_autoload(st):
    """Nếu thư mục hiện tại có private.key thì hỏi có nạp không."""
    if os.path.isfile("private.key") and confirm("Tìm thấy private.key trong thư mục hiện tại. Nạp luôn?", True):
        act_load(st, "private.key")

def main():
    setup_console()
    st = State()
    actions = {k: item[1] for k, item in MENU if item}
    print("Chào mừng đến với chương trình minh hoạ hệ mã MHK (chỉ dùng cho học tập, MHK KHÔNG an toàn).")
    try:
        maybe_autoload(st)
    except (EOFError, KeyboardInterrupt):
        print("\nTạm biệt.")
        return
    while True:
        print_menu(st)
        try:
            choice = input("Chọn chức năng: ").strip()
        except (EOFError, KeyboardInterrupt):
            print("\nTạm biệt.")
            return
        if choice == "0":
            print("Tạm biệt.")
            return
        action = actions.get(choice)
        if action is None:
            err("Lựa chọn không hợp lệ. Hãy nhập một số trong menu.")
            continue
        print()
        try:
            action(st)
            pause()
        except KeyboardInterrupt:
            print("\n(Đã huỷ thao tác.)")
        except EOFError:
            print("\nTạm biệt.")
            return
        except Exception as exc:                                   # noqa: BLE001
            err(f"Có lỗi không mong đợi: {exc}")


if __name__ == "__main__":
    main()

        
