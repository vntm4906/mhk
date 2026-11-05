import os
import sys

from mhk_core import keygen_random
from mhk_io import save_keys

N_MIN, N_MAX = 4, 256


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    force = "--ghi-de" in sys.argv[1:]
    try:
        n = int(args[0]) if args else 64
    except ValueError:
        sys.exit("Lỗi: N phải là số nguyên. Cách dùng: python src/create_key.py [N] [--ghi-de]")
    if not N_MIN <= n <= N_MAX:
        sys.exit(f"Lỗi: N phải nằm trong khoảng {N_MIN} đến {N_MAX}.")

    existing = [f for f in ("public.key", "private.key") if os.path.exists(f)]
    if existing and not force:
        print(f"Cảnh báo: đã có {', '.join(existing)}. Ghi đè sẽ làm mất khoá cũ, "
              "bản mã cũ sẽ KHÔNG giải mã được nữa.")
        if not sys.stdin.isatty():
            sys.exit("Đã huỷ. Thêm --ghi-de nếu chắc chắn muốn ghi đè.")
        if input("Ghi đè? (c = có, k = không) [k]: ").strip().lower() not in ("c", "co", "có", "y", "yes"):
            sys.exit("Đã huỷ, giữ nguyên khoá cũ.")

    keys = keygen_random(n)
    save_keys(".", keys)
    print(f"Đã tạo public.key và private.key (N = {n})")
    print("Lưu ý: private.key là khoá riêng dạng văn bản thuần, không đưa lên GitHub.")


if __name__ == "__main__":
    main()
