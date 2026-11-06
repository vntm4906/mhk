"""decode.py - Giải mã tệp bản mã (base 64) bằng khóa riêng (private.key).

Cách dùng:
    python src/decode.py <tệp_bản_mã> <tệp_kết_quả>
Cần private.key ĐÚNG CẶP với public.key đã dùng khi mã hóa.
"""
import os
import sys

from mhk_io import load_key_file, safe_decrypt, unpack_ciphertext


def main():
    if len(sys.argv) != 3:
        sys.exit("Cách dùng: python src/decode.py <tệp_bản_mã> <tệp_kết quả>")
    src, dst = sys.argv[1], sys.argv[2]

    try:
        private = load_key_file("private.key")["private"]
    except FileNotFoundError:
        sys.exit("Lỗi: không tìm thấy private.key ở thư mục hiện tại.")
    except (ValueError, KeyError) as exc:
        sys.exit(f"Lỗi: private.key không hợp lệ ({exc}).")
    if private is None:
        sys.exit("Lỗi: tệp private.key không chứa khóa riêng.")

    try:
        with open(src, encoding="ascii") as f:
            text = f.read()
    except FileNotFoundError:
        sys.exit(f"Lỗi: Không tìm thấy tệp bản mã: {src}")
    except UnicodeDecodeError:
        sys.exit("Lỗi: tệp này không phải bản mã base 64 (chứa ký tự ngoài ASCII).")

    try:
        cts, length = unpack_ciphertext(text, private[3])
        plain = safe_decrypt(cts, length, private)
    except ValueError as exc:
        sys.exit(f"Lỗi: {exc}")

    note = " (ghi đè tệp cũ)" if os.path.exists(dst) else ""
    try:
        with open(dst, "wb") as f:
            f.write(plain)
    except OSError as exc:
        sys.exit(f"Lỗi ghi tệp: {exc}")
    print(f"Đã giải mã {length} byte ({len(cts)} khối).")
    print(f"Kết quả: {dst}{note}") 


if __name__ == "__main__":
    main()
