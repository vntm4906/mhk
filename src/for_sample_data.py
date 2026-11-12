import hashlib
import os
import sys
import time
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from mhk_core import decrypt_bytes, encrypt_bytes, keygen_random
from mhk_io import cipher_width, load_key_file, pack_ciphertext, save_keys, unpack_ciphertext

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLE_DIR = os.path.join(ROOT, "sample_data")
RESULTS_DIR = os.path.join(ROOT, "results")
N = 64


def sha(b):
    return hashlib.sha256(b).hexdigest()


def main():
    os.makedirs(RESULTS_DIR, exist_ok=True)

    # Sinh một cặp khoá dùng chung cho cả phiên, lưu vào results/ để tái lập được.
    keys = keygen_random(N)
    save_keys(RESULTS_DIR, keys)
    public = keys["public"]
    private = keys["private"]
    M = public[1]

    files = sorted(f for f in os.listdir(SAMPLE_DIR)
                   if os.path.isfile(os.path.join(SAMPLE_DIR, f)))

    lines = []
    lines.append("KET QUA CHAY SAMPLE_DATA - HE MA MHK")
    lines.append(f"Thoi diem chay : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Python         : {sys.version.split()[0]}")
    lines.append(f"He dieu hanh    : {sys.platform}")
    lines.append(f"Kich thuoc khoi N = {N}, M co {M.bit_length()} bit")
    lines.append("Khoa luu tai   : results/public.key, results/private.key")
    lines.append("=" * 70)
    header = f"{'Tep':26} {'Byte goc':>9} {'So khoi':>8} {'Ma hoa(s)':>10} {'Giai ma(s)':>11} {'SHA-256':>9}"
    lines.append(header)
    lines.append("-" * 70)

    all_ok = True
    for name in files:
        src = os.path.join(SAMPLE_DIR, name)
        with open(src, "rb") as fh:
            data = fh.read()

        t0 = time.perf_counter()
        cts, length = encrypt_bytes(data, public)
        t1 = time.perf_counter()
        plain = decrypt_bytes(cts, private, length)
        t2 = time.perf_counter()

        # Ghi tep ban ma (base64) va tep giai ma vao results/
        enc_path = os.path.join(RESULTS_DIR, name + ".mhk")
        with open(enc_path, "w") as fh:
            fh.write(pack_ciphertext(cts, length, M))
        dec_path = os.path.join(RESULTS_DIR, "giaima_" + name)
        with open(dec_path, "wb") as fh:
            fh.write(plain)

        ok = sha(data) == sha(plain)
        all_ok = all_ok and ok
        lines.append(f"{name:26} {length:>9} {len(cts):>8} "
                     f"{t1 - t0:>10.4f} {t2 - t1:>11.4f} {'KHOP' if ok else 'KHAC':>9}")

    lines.append("-" * 70)
    lines.append(f"Ket luan: {'TAT CA giai ma khop tep goc (SHA-256).' if all_ok else 'CO TEP KHAC - xem lai.'}")
    lines.append("Luu y: thoi gian phu thuoc may; ban mac dai gap ~2 lan ban ro.")

    report = os.path.join(RESULTS_DIR, "bao_cao_sample_data.txt")
    with open(report, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")

    print("\n".join(lines))
    print(f"\nDa ghi bao cao: {report}")
    print(f"Da ghi ban ma va tep giai ma vao: {RESULTS_DIR}")


if __name__ == "__main__":
    main()
