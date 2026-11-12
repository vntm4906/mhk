import os
import secrets
import time

from mhk_attack import METHODS, crack_blocks, density, run_method
from mhk_cli import (LINE, THIN, ask, ask_int, ask_path, confirm, err, pause,
                     setup_console, wrap)
from mhk_core import bits_to_bytes, encrypt_block, keygen_from_params, keygen_random
from mhk_io import load_key_file, parse_int_list, unpack_ciphertext

METHOD_KEYS = {"6": "brute", "7": "mitm", "8": "lll"}

def bits_str(bits):
    return "".join(map(str, bits))

def method_allowed(key, n):
    cap = METHODS[key][2]
    return cap is None or n <= cap

class Problem:
    """Bài toán tấn công: khoá công khai (S, M), bản mã C, bản rõ gốc P nếu biết."""

    def __init__(self, S, M, C, P=None, source=""):
        self.S, self.M, self.C, self.P, self.source = S, M, C % M, P, source

    @property
    def n(self):
        return len(self.S)

class AttackSession:
    def __init__(self, public=None):
        self.public = public        # khoá công khai do menu chính truyền sang (nếu có)
        self.prob = None

    # ------------------------------------------------------------ hiển thị
    def status(self):
        if self.prob is None:
            return "Bài toán hiện tại: (chưa có) - hãy chọn mục 1 đến 4"
        p = self.prob
        known = bits_str(p.P) if p.P is not None else "không biết"
        return (f"Bài toán: N = {p.n}, mật độ ≈ {density(p.S):.2f}, C = {p.C}\n"
                f"Nguồn: {p.source} | Bản rõ gốc (chỉ để đối chiếu): {known}")

    def show_problem(self):
        if self.prob is None:
            err("Chưa có bài toán.")
            return
        p = self.prob
        print(THIN)
        print(f"N = {p.n}")
        print(f"M = {p.M}")
        wrap("S (khoá công khai)", p.S)
        print(f"C (bản mã cần phá) = {p.C}")
        print(f"Mật độ ba lô ≈ {density(p.S):.2f} (mật độ thấp thì tấn công dàn hiệu quả)")
        print(f"Bản rõ gốc: {bits_str(p.P) if p.P is not None else 'không biết'}")
        print(THIN)

    # ------------------------------------------------------------ chuẩn bị bài toán
    def use_example(self):
        keys = keygen_from_params([2, 3, 6, 12, 25], 53, 46)
        S, M = keys["public"]
        P = [0, 1, 0, 0, 1]
        self.prob = Problem(S, M, encrypt_block(P, (S, M)), P, "ví dụ BTVD2")
        print("Đã nạp ví dụ BTVD2: S = (39, 32, 11, 22, 37), M = 53, C = 16.")
        print("Kẻ tấn công chỉ biết S, M, C và phải tìm lại P = 01001 mà không có A', u.")
        self.show_problem()

    def random_problem(self):
        n = ask_int("Số bit mỗi khối N", 32, 4, 96)
        S, M = keygen_random(n)["public"]
        P = [secrets.randbelow(2) for _ in range(n)]
        self.prob = Problem(S, M, encrypt_block(P, (S, M)), P, f"khoá ngẫu nhiên N = {n}")
        self.show_problem()

    def from_public_key(self):
        public = None
        if self.public is not None and confirm("Dùng khoá công khai đang có trong menu chính?", True):
            public = self.public
            source = "khoá của menu chính"
        else:
            path = ask_path("Đường dẫn public.key (hoặc private.key)", "public.key")
            try:
                public = load_key_file(path)["public"]
            except FileNotFoundError:
                err(f"Không tìm thấy tệp: {path}")
                return
            except Exception as exc:                               # noqa: BLE001
                err(f"Không nạp được khoá: {exc}")
                return
            source = f"tệp {path}"
        S, M = public
        print(f"Khoá có N = {len(S)}.")
        print("  1. Chương trình chọn bản rõ ngẫu nhiên    2. Tự nhập bản rõ (dãy bit)")
        if ask("Chọn", "1") == "2":
            s = ask(f"Bản rõ ({len(S)} ký tự 0/1)")
            if len(s) != len(S) or set(s) - {"0", "1"}:
                err(f"Phải nhập đúng {len(S)} ký tự gồm 0 và 1.")
                return
            P = [int(ch) for ch in s]
        else:
            P = [secrets.randbelow(2) for _ in S]
        self.prob = Problem(S, M, encrypt_block(P, (S, M)), P, source)
        self.show_problem()

    def manual_problem(self):
        print("Nhập bài toán của người khác: chỉ có khoá công khai S, M và bản mã C.")
        try:
            S = parse_int_list(ask("S (các số cách nhau bởi dấu phẩy)"))
            M = int(ask("M"))
            C = int(ask("C"))
        except ValueError:
            err("S, M, C phải là số nguyên.")
            return
        if len(S) < 2 or M <= 1 or any(s <= 0 for s in S):
            err("S cần ít nhất 2 phần tử dương và M > 1.")
            return
        self.prob = Problem(S, M, C, None, "nhập tay")
        self.show_problem()

    # ------------------------------------------------------------ tấn công một bản mã
    def attack(self, key):
        if self.prob is None:
            err("Chưa có bài toán. Hãy chọn mục 1 đến 4 trước.")
            return
        p = self.prob
        name = METHODS[key][0]
        if not method_allowed(key, p.n):
            err(f"{name} chỉ cho phép N <= {METHODS[key][2]} (N = {p.n} cần quá nhiều thời gian/bộ nhớ).")
            return
        cost = {"brute": f"2^{p.n} = {2 ** p.n:,} tổ hợp",
                "mitm": f"khoảng 2 x 2^{p.n // 2} = {2 * 2 ** (p.n // 2):,} tổng con",
                "lll": f"quy giản dàn số chiều {p.n + 2}, thời gian đa thức"}[key]
        print(f"Phương pháp: {name} | Chi phí: {cost}")
        print("Đang chạy... (Ctrl+C để dừng)")
        try:
            sols, secs = run_method(key, p.S, p.M, p.C)
        except KeyboardInterrupt:
            print("\nĐã dừng.")
            return
        print(THIN)
        print(f"Thời gian: {secs:.4f} giây | Số nghiệm tìm được: {len(sols)}")
        if not sols:
            print("Không tìm được nghiệm. (LLL là tấn công xác suất; hãy thử lại hoặc đổi bài toán.)")
        for i, bits in enumerate(sols[:5], 1):
            ok = encrypt_block(bits, (p.S, p.M)) == p.C
            line = f"  Nghiệm {i}: {bits_str(bits)} | mã hoá lại ra đúng C: {'có' if ok else 'KHÔNG'}"
            if p.P is not None:
                line += f" | trùng bản rõ gốc: {'CÓ' if bits == p.P else 'không'}"
            print(line)
        if len(sols) > 5:
            print(f"  ... và {len(sols) - 5} nghiệm khác")
        if len(sols) > 1:
            print("  Lưu ý: có nhiều nghiệm, kẻ tấn công không phân biệt được bản rõ thật.")
        if sols and p.P is not None and sols[0] == p.P:
            print("=> Đã khôi phục bản rõ CHỈ từ khoá công khai và bản mã, không cần khoá riêng.")
        print(THIN)

    # ------------------------------------------------------------ phá cả tệp bản mã
    def crack_file(self):
        print("Mô phỏng kẻ tấn công: chỉ có public.key và tệp bản mã (do encode.py hoặc menu chính tạo).")
        if self.public is not None and confirm("Dùng khoá công khai đang có trong menu chính?", True):
            public = self.public
        else:
            path = ask_path("Đường dẫn public.key", "public.key")
            try:
                public = load_key_file(path)["public"]
            except FileNotFoundError:
                err(f"Không tìm thấy tệp: {path}")
                return
            except Exception as exc:                               # noqa: BLE001
                err(f"Không nạp được khoá: {exc}")
                return
        S, M = public
        n = len(S)
        cpath = ask_path("Tệp bản mã cần phá (.mhk)")
        try:
            with open(cpath, encoding="ascii") as f:
                cts, length = unpack_ciphertext(f.read(), M)
        except FileNotFoundError:
            err(f"Không tìm thấy tệp: {cpath}")
            return
        except UnicodeDecodeError:
            err("Tệp này không phải bản mã base64.")
            return
        except ValueError as exc:
            err(f"{exc} (bản mã có thể được tạo bằng khoá công khai khác)")
            return
        if length > len(cts) * n // 8:
            err("Độ dài gốc trong bản mã không khớp khoá này (sai khoá công khai?).")
            return

        options = [k for k in ("lll", "mitm", "brute") if method_allowed(k, n)]
        labels = {"lll": "1. LLL", "mitm": "2. Meet-in-the-middle", "brute": "3. Vét cạn"}
        print("Phương pháp có thể dùng với N = %d: %s" % (n, ", ".join(labels[k] for k in options)))
        key = {"1": "lll", "2": "mitm", "3": "brute"}.get(ask("Chọn phương pháp", "1"))
        if key not in options:
            err("Phương pháp không hợp lệ hoặc vượt giới hạn với N này.")
            return
        total = len(cts)
        k = ask_int(f"Phá bao nhiêu khối đầu tiên? (tệp có {total} khối, {length} byte)", total, 1, total)

        print(f"Đang phá {k} khối bằng {METHODS[key][0]}... (Ctrl+C để dừng)")
        recovered, failed, ambiguous, t_total = [], 0, 0, 0.0
        try:
            for i, bits, nsol, secs in crack_blocks(S, M, cts[:k], key):
                t_total += secs
                if bits is None:
                    failed += 1
                    bits = [0] * n
                if nsol > 1:
                    ambiguous += 1
                recovered.extend(bits)
                done = i + 1
                if done == 1 or done % 5 == 0 or done == k:
                    eta = t_total / done * (k - done)
                    print(f"  Đã phá {done}/{k} khối | {t_total:.1f} s | còn khoảng {eta:.0f} s")
        except KeyboardInterrupt:
            print("\nĐã dừng giữa chừng; giữ lại phần đã phá được.")
        if not recovered:
            return
        n_bytes = min(length, len(recovered) // 8)
        data = bits_to_bytes(recovered)[:n_bytes]
        print(THIN)
        print(f"Kết quả: {len(recovered) // n}/{total} khối, {n_bytes} byte, tổng {t_total:.2f} giây.")
        print(f"Khối không phá được: {failed} | Khối có nhiều nghiệm: {ambiguous}")
        preview = data[:400].decode("utf-8", errors="replace")
        if preview and sum(ch.isprintable() or ch in "\n\r\t" for ch in preview) / len(preview) > 0.9:
            print("Xem trước nội dung khôi phục được:")
            print(preview + (" ..." if len(data) > 400 else ""))
        else:
            print("(Dữ liệu nhị phân, ví dụ ảnh: hãy mở tệp kết quả để xem.)")

        base = cpath[:-4] if cpath.endswith(".mhk") else cpath
        root, ext = os.path.splitext(base)
        out = ask_path("Lưu dữ liệu khôi phục vào", f"{root}_pha_ma{ext}")
        if os.path.exists(out) and not confirm(f"Tệp {out} đã tồn tại. Ghi đè?"):
            print("Không lưu.")
        else:
            try:
                with open(out, "wb") as f:
                    f.write(data)
                print(f"Đã ghi: {out}")
            except OSError as exc:
                err(f"Lỗi ghi tệp: {exc}")
        orig = ask_path("Đối chiếu với tệp gốc (Enter để bỏ qua)")
        if orig:
            try:
                with open(orig, "rb") as f:
                    ref = f.read()
                same = ref[:len(data)] == data
                full = same and len(data) == len(ref)
                print("So với tệp gốc: " + ("GIỐNG HỆT toàn bộ" if full else
                                            "giống hệt phần đã phá" if same else "KHÁC (có khối sai)"))
            except OSError as exc:
                err(f"Không đọc được tệp gốc: {exc}")
        print(THIN)

    # ------------------------------------------------------------ so sánh thời gian
    def compare(self):
        sizes = [8, 12, 16, 20, 24, 32, 40, 48, 64]
        print("So sánh ba phương pháp, mỗi N dùng một khoá ngẫu nhiên mới. (Ctrl+C để dừng)")
        print(f"{'N':>4} | {'Vét cạn':>10} | {'Meet-in-middle':>14} | {'LLL':>9} | LLL đúng bản rõ")
        try:
            for n in sizes:
                S, M = keygen_random(n)["public"]
                P = [secrets.randbelow(2) for _ in range(n)]
                C = encrypt_block(P, (S, M))
                cells, ok = {}, ""
                for key in ("brute", "mitm", "lll"):
                    if not method_allowed(key, n) or (key == "brute" and n > 20):
                        cells[key] = "-"
                        continue
                    sols, secs = run_method(key, S, M, C)
                    cells[key] = f"{secs:.3f}s"
                    if key == "lll":
                        ok = "có" if P in sols else "KHÔNG"
                print(f"{n:>4} | {cells['brute']:>10} | {cells['mitm']:>14} | {cells['lll']:>9} | {ok}")
        except KeyboardInterrupt:
            print("\nĐã dừng.")
        print("Dấu - : bỏ qua vì quá lâu hoặc vượt giới hạn. Thời gian phụ thuộc máy.")

MENU = [
    ("CHUẨN BỊ BÀI TOÁN", None),
    ("1", "Dùng ví dụ BTVD2 (S = 39,32,11,22,37; M = 53; C = 16)"),
    ("2", "Sinh bài toán ngẫu nhiên (chọn N)"),
    ("3", "Dùng khoá công khai (public.key / khoá menu chính) và mã hoá một bản rõ"),
    ("4", "Nhập tay S, M, C"),
    ("5", "Xem bài toán hiện tại"),
    ("TẤN CÔNG MỘT BẢN MÃ", None),
    ("6", "Vét cạn (N <= 22)"),
    ("7", "Meet-in-the-middle (N <= 44)"),
    ("8", "Quy giản dàn LLL (N lớn)"),
    ("MINH HOẠ NÂNG CAO", None),
    ("9", "Phá cả tệp bản mã chỉ với khoá công khai"),
    ("10", "So sánh thời gian ba phương pháp theo N"),
]

def attack_menu(public=None, back_label="Quay lại / thoát"):
    """Vòng lặp menu tấn công. public: khoá công khai (S, M) truyền từ menu chính, nếu có."""
    ss = AttackSession(public)
    actions = {"1": ss.use_example, "2": ss.random_problem, "3": ss.from_public_key,
               "4": ss.manual_problem, "5": ss.show_problem, "9": ss.crack_file, "10": ss.compare}
    for k, method in METHOD_KEYS.items():
        actions[k] = (lambda m=method: ss.attack(m))
    while True:
        print()
        print(LINE)
        print("   MENU TẤN CÔNG HỆ MÃ MHK (chỉ dùng cho học tập)")
        print(LINE)
        print(ss.status())
        print(THIN)
        for key, label in MENU:
            print(f" [{key}]" if label is None else f"  {key:>2}. {label}")
        print(f"   0. {back_label}")
        print(THIN)
        choice = input("Chọn chức năng: ").strip()
        if choice == "0":
            return
        action = actions.get(choice)
        if action is None:
            err("Lựa chọn không hợp lệ.")
            continue
        print()
        try:
            action()
            pause()
        except KeyboardInterrupt:
            print("\n(Đã huỷ thao tác.)")

def main():
    setup_console()
    print("Menu tấn công hệ mã MHK. Kẻ tấn công chỉ có khoá công khai và bản mã.")
    try:
        attack_menu(back_label="Thoát")
    except (EOFError, KeyboardInterrupt):
        pass
    print("Tạm biệt.")

if __name__ == "__main__":
    main()

