# Hệ mã ba lô Merkle–Hellman (MHK)

Bài tập nhóm môn **An toàn bảo mật thông tin**, Đại học Kinh tế Quốc dân.

> **Cảnh báo:** MHK là hệ mã **không an toàn** và đã bị phá. Mã nguồn chỉ phục vụ học tập, **không** dùng để bảo vệ dữ liệu thật. Các chức năng tấn công chỉ dùng trên khoá và bản mã do chính chương trình tạo ra.


---

## 1. Cấu trúc dự án

```
mhk-knapsack-demo/
├── README.md                    Tệp này
├── requirements.txt             Yêu cầu môi trường (không cần thư viện ngoài)
├── .gitignore                   Chặn khoá, bản mã, tệp kết quả khỏi Git
├── .gitmessage                  Mẫu thông điệp commit
├── src/
│   ├── mhk_core.py              LÕI thuật toán: sinh khoá, mã hoá, giải mã (không có giao diện)
│   ├── mhk_io.py                Đọc/ghi khoá, đóng gói bản mã base64, diễn giải từng bước
│   ├── mhk_attack.py            Thuật toán tấn công: vét cạn, meet-in-the-middle, quy giản dàn LLL
│   ├── create_key.py            Dòng lệnh: sinh khoá
│   ├── encode.py                Dòng lệnh: mã hoá tệp
│   ├── decode.py                Dòng lệnh: giải mã tệp
│   ├── mhk_cli.py               Menu chính trong cmd (15 chức năng)
│   ├── mhk_attack_cli.py        Menu tấn công trong cmd (10 chức năng)
│   └── for_sample_data.py       Chạy toàn bộ sample_data, ghi kết quả vào results/
├── sample_data/
│   ├── vanban.txt               Văn bản tiếng Việt, 2053 byte
│   ├── anh_nho.png              Ảnh xám 64×64, 346 byte
│   ├── vi_du_tinh_tay.txt       Bản tính tay đầy đủ: BTVD1, BTVD2, ví dụ "NEU"
│   └── vi_du_tinh_tay_so.txt    Chỉ các con số của ví dụ tính tay, 89 byte
└── results/                     Nơi lưu kết quả chạy và đo đạc
```

**Phụ thuộc:** `mhk_core.py` là tệp then chốt. Ba chương trình dòng lệnh và hai menu đều cần `mhk_core.py` và `mhk_io.py`; menu tấn công cần thêm `mhk_attack.py`; mục chạy sample_data cần `for_sample_data.py`. **Giữ các tệp trong `src/` cùng một thư mục.**

---

## 2. Chuẩn bị

1. **Python 3.8 trở lên:** `python --version`. Windows có thể dùng `py`; macOS/Linux dùng `python3`.
2. Không cần cài thư viện nào. Phần lõi **không dùng thư viện mật mã**; `hashlib` (SHA-256) chỉ dùng để đối chiếu toàn vẹn.
3. Tiếng Việt trên cmd Windows: chạy `chcp 65001` và đặt phông chữ **Consolas**.
4. **Mọi lệnh chạy từ thư mục gốc của repo.** Khoá `public.key`, `private.key` được tạo và đọc ở thư mục hiện tại.

```
git clone https://github.com/<tai-khoan>/<ten-repo>.git
cd <ten-repo>
```

---

## 3. Bắt đầu nhanh

```
python src/create_key.py 64
python src/encode.py sample_data/vanban.txt vanban.txt.mhk
python src/decode.py vanban.txt.mhk vanban_ket_qua.txt
```

Kiểm tra: Windows `fc /b sample_data\vanban.txt vanban_ket_qua.txt` (mong đợi "no differences encountered"); macOS/Linux `cmp sample_data/vanban.txt vanban_ket_qua.txt` (không in gì là giống hệt).

Sau đó mở hai menu:

```
python src/mhk_cli.py          # menu chính
python src/mhk_attack_cli.py   # menu tấn công (cũng mở được từ mục 13 của menu chính)
```

---

## 4. Ba chương trình dòng lệnh

Thứ tự bắt buộc: **tạo khoá → mã hoá → giải mã**.

### 4.1. `create_key.py` — sinh khoá

```
python src/create_key.py [N] [--ghi-de]
```

| Tham số | Ý nghĩa |
|---|---|
| `N` | Số bit mỗi khối, từ 4 đến 256, mặc định 64 |
| `--ghi-de` | Ghi đè khoá cũ không hỏi |

Kết quả: `public.key` (khoá công khai S, M) và `private.key` (khoá riêng A', u, u⁻¹, M). Nếu đã có khoá, chương trình **hỏi xác nhận** trước khi ghi đè.

### 4.2. `encode.py` — mã hoá tệp

```
python src/encode.py <tệp_bản_rõ> <tệp_bản_mã>
```

Cần `public.key`. Đọc tệp theo **byte** nên dùng được với mọi loại tệp. Bản mã ghi dạng base64.

### 4.3. `decode.py` — giải mã tệp

```
python src/decode.py <tệp_bản_mã> <tệp_kết_quả>
```

Cần `private.key` **đúng cặp** với `public.key` đã dùng khi mã hoá.

### 4.4. Kết quả đo được với dữ liệu mẫu (N = 64)

| Tệp | Kích thước gốc | Số khối |
|---|---|---|
| `vanban.txt` | 2 053 byte | 257 |
| `anh_nho.png` | 346 byte | 44 |
| `vi_du_tinh_tay.txt` | 3 920 byte | 490 |
| `vi_du_tinh_tay_so.txt` | 89 byte | 12 |

Mỗi khối bản mã chiếm 16 byte với N = 64, nên bản mã dài khoảng gấp đôi bản rõ.

---

## 5. Menu chính: `src/mhk_cli.py`

Gõ số rồi Enter; sau mỗi chức năng nhấn Enter để quay lại; `0` để thoát; **Ctrl+C** huỷ thao tác đang chạy. Nếu thư mục có `private.key`, chương trình hỏi có nạp luôn không.

| Mục | Chức năng | Ghi chú |
|---|---|---|
| 1 | Sinh khoá ngẫu nhiên | Nhập N (Enter = 64) |
| 2 | Nhập tham số thủ công | A' (cách nhau bằng dấu phẩy), M, u; sai điều kiện thì báo lý do |
| 3 | Nạp ví dụ BTVD2 | A' = 2,3,6,12,25; M = 53; u = 46 |
| 4 | Xem khoá hiện tại | In S, M, A', u, u⁻¹ và 4 dòng kiểm tra điều kiện |
| 5 | Lưu khoá ra tệp | Hỏi trước khi ghi đè |
| 6 | Nạp khoá từ tệp | `private.key`: dùng đủ; `public.key`: chỉ mã hoá |
| 7 | Một khối, từng bước | Với BTVD2 nhập `01001` → C = 16, C' = 28 |
| 8 | Mã hoá văn bản | Gõ nhiều dòng, kết thúc bằng một dòng trống |
| 9 | Giải mã văn bản | Dán base64, hoặc `@đường_dẫn_tệp` |
| 10 | Mã hoá tệp | Tên gợi ý `<tệp>.mhk`; giới hạn 5 MB |
| 11 | Giải mã tệp | |
| 12 | Kiểm tra vòng | Mã hoá rồi giải mã trong bộ nhớ, so SHA-256, không ghi tệp |
| 13 | **Menu tấn công** | Mở `mhk_attack_cli.py`, truyền sẵn khoá công khai hiện tại |
| 14 | Đo thời gian | Bảng thời gian mã hoá/giải mã từ 1 000 đến 500 000 byte |
| 15 | **Chạy toàn bộ sample_data** | Gọi `for_sample_data.py`, ghi kết quả vào `results/` (xem mục 7) |

---

## 6. Menu tấn công: `src/mhk_attack_cli.py`

Mở riêng bằng `python src/mhk_attack_cli.py`, hoặc từ mục 13 của menu chính. **Kẻ tấn công chỉ có khoá công khai (S, M) và bản mã.** Bản rõ gốc chỉ dùng để đối chiếu sau khi tấn công xong.

| Mục | Chức năng | Ghi chú |
|---|---|---|
| 1 | Dùng ví dụ BTVD2 | S = 39,32,11,22,37; M = 53; C = 16 |
| 2 | Sinh bài toán ngẫu nhiên | Chọn N từ 4 đến 96 |
| 3 | Dùng khoá công khai | Từ `public.key` hoặc từ menu chính; bản rõ ngẫu nhiên hoặc tự nhập |
| 4 | Nhập tay S, M, C | Bài toán của người khác, không biết bản rõ |
| 5 | Xem bài toán hiện tại | |
| 6 | Vét cạn | O(2^N), chỉ cho N ≤ 22 |
| 7 | Meet-in-the-middle | O(2^(N/2)), chỉ cho N ≤ 44 |
| 8 | Quy giản dàn LLL | Thời gian đa thức; tấn công **xác suất**, đôi khi phải chạy lại |
| 9 | **Phá cả tệp bản mã** | Chỉ cần `public.key` và tệp `.mhk`; chọn số khối; xem trước, lưu và đối chiếu với tệp gốc |
| 10 | So sánh thời gian | Bảng ba phương pháp theo N = 8 đến 64 |

---

## 7. Chạy toàn bộ sample_data và ghi kết quả vào `results/`

Hai cách, cho cùng kết quả.

**Cách 1 — qua menu chính:** mở `python src/mhk_cli.py`, chọn **mục 15**, Enter để xác nhận.

**Cách 2 — chạy thẳng script:**

```
python src/for_sample_data.py
```

Cả hai sẽ: sinh một cặp khoá N = 64 (lưu vào `results/`), mã hoá rồi giải mã **mọi tệp** trong `sample_data/`, so SHA-256, đo thời gian, rồi ghi vào `results/`:

- `bao_cao_sample_data.txt` — bảng kết quả. Tệp này **được đưa lên GitHub**.
- các tệp bản mã `*.mhk`, bản giải mã `giaima_*`, `public.key`, `private.key` — **bị `.gitignore` chặn**, không lên GitHub.

Mẫu báo cáo:

```
Tep                         Byte goc  So khoi  Ma hoa(s)  Giai ma(s)   SHA-256
----------------------------------------------------------------------
anh_nho.png                      346       44     0.0005      0.0003      KHOP
vanban.txt                      2053      257     0.0026      0.0019      KHOP
vi_du_tinh_tay.txt              3920      490     0.0038      0.0026      KHOP
vi_du_tinh_tay_so.txt             89       12     0.0001      0.0001      KHOP
```

Cột byte và số khối giống nhau trên mọi máy; cột thời gian phụ thuộc máy. Mục 15 **không** làm thay đổi khoá đang dùng trong menu chính.

Đưa kết quả lên GitHub:

```
git add results/bao_cao_sample_data.txt
git status
git commit -m "test(sample): them ket qua chay sample_data"
```

Chạy `git status` để chắc chắn không thấy `public.key`, `private.key`, `*.mhk`, `giaima_*`.

---

## 8. Dữ liệu mẫu

- `vi_du_tinh_tay.txt`: bản tính tay đầy đủ để đối chiếu với chương trình. Ví dụ 2 (BTVD2) được tái hiện chính xác ở menu chính (mục 3 rồi mục 7). Ví dụ 3 ("NEU", 5 bit/ký tự) minh hoạ nguyên lý theo ghi chú cuối slide; chương trình mã hoá theo byte nên **không** tái hiện đúng các số của ví dụ 3.
- `vi_du_tinh_tay_so.txt`: chỉ các con số, dùng để thử nhanh.
- `vanban.txt`, `anh_nho.png`: dữ liệu thật để demo.

---

## 9. Xử lý lỗi thường gặp

| Thông báo | Nguyên nhân và cách xử lý |
|---|---|
| `ModuleNotFoundError: No module named 'mhk_core'` | Các tệp trong `src/` không cùng thư mục |
| `Lỗi: không tìm thấy public.key ...` | Chưa chạy `create_key.py`, hoặc đang đứng sai thư mục |
| `Lỗi: không tìm thấy tệp bản rõ: ...` | Sai tên tệp; Windows hay ẩn đuôi, tệp có thể là `xxx.txt.txt` |
| `Giải mã thất bại ...` | Giải mã bằng khoá khác khoá đã mã hoá (thường do sinh lại khoá) |
| `Thiếu src/for_sample_data.py ...` | Mục 15 cần tệp này trong `src/` |
| Chữ tiếng Việt thành dấu `?` trên cmd | Chạy `chcp 65001` và dùng phông Consolas |
| LLL báo "Không tìm được nghiệm" | Tấn công xác suất; chạy lại hoặc đổi bài toán |
