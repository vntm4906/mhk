"""encode.py - Mã hóa một tệp bằng khóa công khai (public.key), bản mã lưu dạng base64.

Cách dùng:
    python src/encode.py <tệp_bản_rõ> <tệp_bản_mã>
Cần public.key ở thư mục hiện tại (tạo bằng create_key.py).
"""
import os
import sys

from mhk_core import encrypt_bytes
from mhk_io import cipher_width, load_key_file, pack_ciphertext


def main():
    if len(sys.argv) != 3:
        sys.exit("Cách dùng: python src/encode.py <tệp_bản_rõ> <tệp_bản_mã>")
    src, dst = sys.argv[1], sys.argv[2]

    try:
        public = load_key_file("public.key")["public"]
    except FileNotFoundError:
        sys.exit("Lỗi: không tìm thấy public.key ở thư mục hiện tại. "
                 "Hãy chạy create_key.py trước, hoặc đứng đúng thư mục.")
    except (ValueError, KeyError) as exc:
        sys.exit(f"Lỗi: public.key không hợp lệ ({exc}).")

    try:
        with open(src, "rb") as f:
            data = f.read()
    except FileNotFoundError:
        sys.exit(f"Lỗi: không tìm thấy tệp bản rõ: {src}")
    except OSError as exc:
        sys.exit(f"Lỗi đọc tệp: {exc}")

    cts, length = encrypt_bytes(data, public)
    note = " (ghi đè tệp cũ)" if os.path.exists(dst) else ""
    try:
        with open(dst, "w") as f:
            f.write(pack_ciphertext(cts, length, public[1]))
    except OSError as exc:
        sys.exit(f"Lỗi ghi tệp: {exc}")

    w = cipher_width(public[1])
    print(f"Đã mã hoá {length} byte thành {len(cts)} khối ({w} byte/khối).")
    print(f"Bản mã: {dst}{note}")


if __name__ == "__main__":
    main()
