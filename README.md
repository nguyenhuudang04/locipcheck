# SOC IOC Enrichment Tool

> Công cụ tra cứu Indicator of Compromise (IOC) tự động cho SOC Analyst.  
> Hỗ trợ: **IPv4 · IPv6 · Domain · URL · MD5 · SHA1 · SHA256**

---

## Tính năng

| Nguồn | Loại IOC | Ghi chú |
|-------|----------|---------|
| GreyNoise Community | IP | Phân loại noise / malicious |
| AbuseIPDB | IP | Điểm tín nhiệm lạm dụng |
| VirusTotal v3 | IP · Domain · URL · Hash | Lookup-only, không upload |
| urlscan.io | Domain · URL | Search-only, không submit scan |

- **Nhận diện IOC tự động** bằng stdlib + regex an toàn
- **Risk Score 0–100** minh bạch với bảng chi tiết từng yếu tố
- **Không tự động block IP, không upload IOC nội bộ**
- Xuất báo cáo **JSON** và **Markdown** vào thư mục `reports/`
- Bỏ qua nguồn thiếu API key, không crash

---

## Cài đặt (Windows PowerShell)

### 1. Clone / tải project

```powershell
cd "C:\Users\DELL\Desktop\TOOL SOC\soc-ioc-enrichment"
```

### 2. Tạo virtual environment

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> Nếu bị lỗi policy:
> ```powershell
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
> ```

### 3. Cài dependencies

```powershell
pip install -r requirements.txt
```

### 4. Cấu hình API keys

```powershell
Copy-Item .env.example .env
notepad .env
```

Điền API key vào file `.env`:

```env
GREYNOISE_API_KEY=your_key_here
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
URLSCAN_API_KEY=your_key_here
```

> **Lưu ý:** Tool vẫn chạy được nếu thiếu một số key — nguồn đó sẽ bị bỏ qua.

---

## Sử dụng

### Tra cứu IP

```powershell
python main.py 185.220.101.5
```

### Tra cứu Domain

```powershell
python main.py malware.example.com
```

### Tra cứu URL

```powershell
python main.py "https://phishing.site/login"
```

### Tra cứu File Hash

```powershell
python main.py d41d8cd98f00b204e9800998ecf8427e
python main.py da39a3ee5e6b4b0d3255bfef95601890afd80709
python main.py e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
```

### Tra cứu nhiều IOC cùng lúc (Hàng loạt / Bulk Check)

Bạn có thể truyền nhiều IOC cách nhau bởi khoảng trắng:
```powershell
python main.py 1.1.1.1 8.8.8.8 evil.com
```

Hoặc đọc danh sách từ một file (mỗi dòng 1 IOC):
```powershell
python main.py -f iocs.txt
```

### Tùy chọn

```powershell
# Lưu report vào thư mục khác
python main.py 8.8.8.8 --output-dir C:\SOC\reports

# Bật verbose logging
python main.py 1.1.1.1 --verbose

# Xem help
python main.py --help
```

---

## Chạy Unit Test

```powershell
# Chạy toàn bộ test
pytest

# Chạy với output chi tiết
pytest -v

# Chạy một file test cụ thể
pytest tests/test_detector.py -v
pytest tests/test_scoring.py -v
pytest tests/test_providers.py -v
```

---

## Cấu trúc Project

```
soc-ioc-enrichment/
├── main.py                  # Entry point CLI
├── requirements.txt         # Dependencies
├── pyproject.toml           # pytest config
├── .env.example             # Template API keys
├── .env                     # API keys thực (KHÔNG commit!)
├── .gitignore
├── README.md
├── reports/                 # Auto-generated reports (JSON + MD)
├── src/
│   ├── __init__.py
│   ├── detector.py          # Nhận diện loại IOC
│   ├── models.py            # Dataclasses kết quả
│   ├── scoring.py           # Risk scoring minh bạch
│   ├── report.py            # Terminal display + file output
│   ├── http_client.py       # HTTP helper (timeout, retry, rate-limit)
│   └── providers/
│       ├── __init__.py
│       ├── greynoise.py     # GreyNoise Community API
│       ├── abuseipdb.py     # AbuseIPDB v2 API
│       ├── virustotal.py    # VirusTotal API v3
│       └── urlscan.py       # urlscan.io Search API
└── tests/
    ├── __init__.py
    ├── test_detector.py     # Test nhận diện IOC
    ├── test_scoring.py      # Test risk scoring
    └── test_providers.py    # Test providers (mock HTTP)
```

---

## Risk Score

| Điểm | Mức độ | Màu |
|------|--------|-----|
| 0–24 | LOW | Xanh |
| 25–49 | MEDIUM | Vàng |
| 50–74 | HIGH | Đỏ |
| 75–100 | CRITICAL | Đỏ đậm |

**Các yếu tố tính điểm được hiển thị rõ ràng:**
- Verdict từ mỗi nguồn
- Số engine VT phát hiện malicious
- Độ tin cậy AbuseIPDB
- Phân loại GreyNoise
- Tags nguy cơ cao (tor, botnet, c2, ransomware, ...)
- Bonus khi nhiều nguồn corroborate
- **Cap 60 điểm khi chỉ có 1 nguồn** (tránh false positive)

---

## Lấy API Key (miễn phí)

| Nguồn | Link đăng ký |
|-------|-------------|
| GreyNoise | https://viz.greynoise.io/account/api-key |
| AbuseIPDB | https://www.abuseipdb.com/register |
| VirusTotal | https://www.virustotal.com/gui/sign-in |
| urlscan.io | https://urlscan.io/user/signup |

---

## Bảo mật

- Không hard-code API key
- Không tự động upload file / submit URL
- Không tự động block IP
- Chỉ query dữ liệu đã tồn tại (GET requests)
- File `.env` được `.gitignore` bảo vệ

---

## Yêu cầu hệ thống

- Python 3.12+
- Windows 10/11 hoặc Linux/macOS
- Kết nối Internet

---

*Được phát triển cho mục đích SOC Analyst — threat intelligence lookup only.*
