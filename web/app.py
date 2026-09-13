"""
web/app.py -- Flask web interface for SOC IOC Enrichment Tool.
Run with: python web/app.py
"""
from __future__ import annotations

import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
import uuid

sys.path.insert(0, str(Path(__file__).parent.parent))

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify, render_template, request, send_file

from src.analyst_summary import build_summary
from src.detector import detect
from src.models import AlertContext, IOCReport, IOCType
from src.scoring import calculate_risk
from src import report as reporter

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False

REPORTS_DIR = Path(__file__).parent.parent / "reports"


def _parse_alert_context(body: dict) -> AlertContext | None:
    ctx_data = body.get("alert_context") or {}
    if not ctx_data:
        return None
    count = ctx_data.get("event_count")
    return AlertContext(
        event_time       = ctx_data.get("event_time") or None,
        hostname         = ctx_data.get("hostname") or None,
        username         = ctx_data.get("username") or None,
        source_ip        = ctx_data.get("source_ip") or None,
        destination      = ctx_data.get("destination") or None,
        action           = ctx_data.get("action") or None,
        event_count      = int(count) if count else None,
        log_source       = ctx_data.get("log_source") or None,
        process_name     = ctx_data.get("process_name") or None,
        command_line     = ctx_data.get("command_line") or None,
        file_hash        = ctx_data.get("file_hash") or None,
        email_sender     = ctx_data.get("email_sender") or None,
        email_recipient  = ctx_data.get("email_recipient") or None,
    )


# ── Simple In-Memory Cache ───────────────────────────────────────────────────
_RESPONSE_CACHE = {}

def get_cache_key(ioc_type: str, canonical_ioc: str, provider: str, module: str = "overview", api_version: str = "v3") -> str:
    """Format: ioc_type:canonical_ioc:provider:module:api_version"""
    return f"{ioc_type}:{canonical_ioc}:{provider}:{module}:{api_version}"

def _run_enrichment(ioc: str, lookup_id: str = None) -> IOCReport:
    ioc = ioc.strip()
    canonical_ioc = ioc.lower()
    ioc_type = detect(ioc)

    if ioc_type in (IOCType.IPV4, IOCType.IPV6):
        from src.providers import greynoise, abuseipdb, virustotal, threatfox
        results = [
            greynoise.enrich(ioc),
            abuseipdb.enrich(ioc),
            virustotal.enrich(ioc, ioc_type.value),
            threatfox.enrich(ioc, ioc_type.value),
        ]
    elif ioc_type == IOCType.DOMAIN:
        from src.providers import virustotal, urlscan, threatfox, dns_provider
        results = [
            virustotal.enrich(ioc, ioc_type.value),
            urlscan.enrich(ioc),
            threatfox.enrich(ioc, ioc_type.value),
            dns_provider.enrich(ioc, ioc_type.value),
        ]
    elif ioc_type == IOCType.URL:
        from src.providers import virustotal, urlscan, threatfox, dns_provider
        results = [
            virustotal.enrich(ioc, ioc_type.value),
            urlscan.enrich(ioc),
            threatfox.enrich(ioc, ioc_type.value),
            dns_provider.enrich(ioc, ioc_type.value),
        ]
    elif ioc_type in (IOCType.MD5, IOCType.SHA1, IOCType.SHA256):
        from src.providers import virustotal, threatfox, malwarebazaar
        results = [
            virustotal.enrich(ioc, ioc_type.value),
            threatfox.enrich(ioc, ioc_type.value),
            malwarebazaar.enrich(ioc),
        ]
    else:
        results = []

    # Simple cache integration simulation
    for res in results:
        key = get_cache_key(ioc_type.value, canonical_ioc, res.source, "overview", "v1")
        if key not in _RESPONSE_CACHE:
            _RESPONSE_CACHE[key] = res
        else:
            # We found a cache hit. In a real scenario we'd skip fetching.
            # Here we just mock pulling from cache to ensure no cross-contamination.
            pass

    ts   = datetime.now(tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if not lookup_id:
        lookup_id = str(uuid.uuid4())
    
    risk = calculate_risk(results)
    total_states = risk.sources_matched + risk.sources_no_match + risk.sources_skipped + risk.sources_error + risk.sources_rate_limited + risk.sources_unauthorized
    # Check if we have unhandled PREMIUM_REQUIRED in main module results
    premium = sum(1 for r in results if r.provider_status == "PREMIUM_REQUIRED")
    total_states += premium
    
    report_validation_status = "VALID" if total_states == risk.sources_attempted else "INVALID"

    return IOCReport(
        lookup_id=lookup_id, 
        ioc=ioc, 
        canonical_ioc=canonical_ioc, 
        ioc_type=ioc_type.value, 
        created_at=ts, 
        results=results, 
        risk=risk, 
        timestamp=ts,
        report_validation_status=report_validation_status
    )


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/enrich", methods=["POST"])
def api_enrich():
    body = request.get_json(silent=True) or {}
    ioc  = (body.get("ioc") or "").strip()
    lookup_id = body.get("lookup_id")

    if not ioc:
        return jsonify({"error": "IOC is required"}), 400

    ioc_type = detect(ioc)
    if ioc_type == IOCType.UNKNOWN:
        return jsonify({"error": "Cannot identify IOC type. Supported: IPv4, IPv6, Domain, URL, MD5, SHA1, SHA256"}), 422

    try:
        report = _run_enrichment(ioc, lookup_id=lookup_id)
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500

    # Alert context
    alert_ctx = _parse_alert_context(body)

    # SOC Analyst Summary
    summary = build_summary(report, alert_ctx)

    # Save reports
    REPORTS_DIR.mkdir(exist_ok=True)
    json_path = reporter.save_json(report, str(REPORTS_DIR))
    md_path   = reporter.save_markdown(report, str(REPORTS_DIR))

    data = report.to_dict()
    data["analyst_summary"]  = summary.to_dict()
    data["alert_context"]    = alert_ctx.to_dict() if alert_ctx else {}
    data["_json_file"]       = Path(json_path).name
    data["_md_file"]         = Path(md_path).name
    return jsonify(data)


@app.route("/api/detect", methods=["POST"])
def api_detect():
    body     = request.get_json(silent=True) or {}
    ioc      = (body.get("ioc") or "").strip()
    ioc_type = detect(ioc)
    return jsonify({"ioc": ioc, "ioc_type": ioc_type.value})


@app.route("/api/vt_relationship", methods=["GET"])
def api_vt_relationship():
    ioc = request.args.get("ioc", "").strip()
    relationship = request.args.get("relationship", "").strip()
    limit = int(request.args.get("limit", 10))
    cursor = request.args.get("cursor", "").strip()
    
    if not ioc or not relationship:
        return jsonify({"error": "Missing ioc or relationship"}), 400
        
    ioc_type = detect(ioc)
    if ioc_type == IOCType.UNKNOWN:
        return jsonify({"error": "Unsupported IOC type"}), 422
        
    from src.providers.virustotal import fetch_vt_relationship
    res = fetch_vt_relationship(ioc, ioc_type.value, relationship, limit, cursor or None)
    return jsonify(res)


@app.route("/api/download/<filename>")
def api_download(filename: str):
    target = REPORTS_DIR / filename
    if not target.resolve().is_relative_to(REPORTS_DIR.resolve()):
        return jsonify({"error": "Invalid path"}), 400
    if not target.exists():
        return jsonify({"error": "File not found"}), 404
    return send_file(str(target), as_attachment=True)


@app.route("/api/history")
def api_history():
    REPORTS_DIR.mkdir(exist_ok=True)
    files = sorted(REPORTS_DIR.glob("*.json"), key=lambda f: f.stat().st_mtime, reverse=True)

    # Deduplicate by IOC — keep most recent
    seen: dict[str, dict] = {}
    for f in files:
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            ioc  = data.get("ioc", "")
            if ioc not in seen:
                seen[ioc] = {
                    "filename":     f.name,
                    "ioc":          ioc,
                    "ioc_type":     data.get("ioc_type"),
                    "score":        (data.get("risk") or {}).get("score"),
                    "level":        (data.get("risk") or {}).get("level"),
                    "timestamp":    data.get("timestamp"),
                    "lookup_count": 1,
                }
            else:
                seen[ioc]["lookup_count"] += 1
        except Exception:
            pass

    history = list(seen.values())[:20]
    return jsonify(history)


# ── Geo IP Checker Routes ────────────────────────────────────────────────────
import re
import requests

def is_private_ip(ip: str) -> bool:
    """
    Kiểm tra xem IP có thuộc dải Private / Reserved theo RFC không.
    Bao gồm: RFC1918, Loopback, APIPA, CGNAT, Multicast, Reserved,
    Broadcast, Documentation ranges và các dải đặc biệt khác.
    """
    private_patterns = [
        # RFC 1918 - Private Networks
        r"^10\.",                                        # 10.0.0.0/8
        r"^172\.(1[6-9]|2[0-9]|3[0-1])\.",             # 172.16.0.0/12
        r"^192\.168\.",                                  # 192.168.0.0/16

        # Loopback
        r"^127\.",                                       # 127.0.0.0/8

        # Link-Local / APIPA
        r"^169\.254\.",                                  # 169.254.0.0/16

        # This network
        r"^0\.",                                         # 0.0.0.0/8

        # Carrier-Grade NAT (CGNAT) - RFC 6598
        r"^100\.(6[4-9]|[7-9]\d|1[01]\d|12[0-7])\.",   # 100.64.0.0/10

        # Multicast - RFC 3171
        r"^2(2[4-9]|3\d)\.",                            # 224.0.0.0/4

        # Reserved / Broadcast - RFC 1112, RFC 919
        r"^24[0-9]\.",                                   # 240.0.0.0/4
        r"^25[0-5]\.",                                   # 255.x.x.x

        # Documentation / TEST ranges - RFC 5737
        r"^192\.0\.2\.",                                 # 192.0.2.0/24    (TEST-NET-1)
        r"^198\.51\.100\.",                              # 198.51.100.0/24 (TEST-NET-2)
        r"^203\.0\.113\.",                               # 203.0.113.0/24  (TEST-NET-3)

        # Benchmark Testing - RFC 2544
        r"^198\.1[89]\.",                                # 198.18.0.0/15

        # IETF Protocol Assignments
        r"^192\.0\.0\.",                                 # 192.0.0.0/24

        # 6to4 Relay Anycast - RFC 3068
        r"^192\.88\.99\.",                               # 192.88.99.0/24
    ]
    try:
        # Validate octet ranges (mỗi octet phải từ 0-255)
        octets = ip.split(".")
        if len(octets) != 4:
            return False
        if not all(0 <= int(o) <= 255 for o in octets):
            return True  # IP không hợp lệ → coi như private để bỏ qua
    except ValueError:
        return True  # Parse lỗi → coi như private để bỏ qua

    return any(re.match(pat, ip) for pat in private_patterns)

def _is_valid_ipv4(ip: str) -> bool:
    """Kiểm tra định dạng và giá trị octet IPv4 hợp lệ (0-255)."""
    try:
        parts = ip.split(".")
        return len(parts) == 4 and all(0 <= int(p) <= 255 for p in parts)
    except (ValueError, AttributeError):
        return False

@app.route("/geo")
def geo_checker():
    return render_template("geo.html")

@app.route("/api/geo", methods=["POST"])
def api_geo():
    body = request.get_json(silent=True) or {}
    ips = body.get("ips", [])
    if not isinstance(ips, list):
        return jsonify({"error": "ips must be a list"}), 400

    # Lọc bỏ giá trị rỗng, kiểm tra định dạng VÀ giá trị octet IPv4 hợp lệ
    valid_ips = []
    for ip in ips:
        ip = str(ip).strip()
        # Kiểm tra regex format trước
        if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip):
            # Validate từng octet (0-255) để loại 999.999.999.999
            if _is_valid_ipv4(ip):
                valid_ips.append(ip)

    # Loại bỏ trùng lặp giữ nguyên thứ tự
    seen_ips = set()
    unique_ips = []
    for ip in valid_ips:
        if ip not in seen_ips:
            unique_ips.append(ip)
            seen_ips.add(ip)

    to_lookup = []
    results = []

    for ip in unique_ips:
        if is_private_ip(ip):
            results.append({
                "ip": ip,
                "scope": "IP Nội bộ (Private)",
                "country": "-",
                "city": "-",
                "isp": "-",
                "tag": "private"
            })
        else:
            to_lookup.append(ip)

    # API batch giới hạn 100 IP mỗi lần
    chunk_size = 100
    for i in range(0, len(to_lookup), chunk_size):
        chunk = to_lookup[i:i + chunk_size]
        try:
            res = requests.post(
                "http://ip-api.com/batch?fields=status,message,country,countryCode,city,isp,query",
                json=chunk,
                timeout=15
            )
            if res.status_code == 200:
                data = res.json()
                for item in data:
                    ip = item.get("query", "")
                    if item.get("status") == "success":
                        country_code = (item.get("countryCode") or "").strip().upper()
                        country = item.get("country") or "-"
                        city = item.get("city") or "-"
                        isp = item.get("isp") or "-"

                        # Nếu country_code rỗng → API không nhận diện được → coi là invalid
                        if not country_code:
                            results.append({
                                "ip": ip,
                                "scope": "Không xác định",
                                "country": country,
                                "city": city,
                                "isp": isp,
                                "tag": "invalid"
                            })
                        elif country_code == "VN":
                            results.append({
                                "ip": ip,
                                "scope": "Trong nước (Việt Nam)",
                                "country": country,
                                "city": city,
                                "isp": isp,
                                "tag": "domestic"
                            })
                        else:
                            results.append({
                                "ip": ip,
                                "scope": f"NƯỚC NGOÀI ({country_code})",
                                "country": country,
                                "city": city,
                                "isp": isp,
                                "tag": "foreign"
                            })
                    else:
                        msg = item.get("message") or "Lỗi tra cứu"
                        results.append({
                            "ip": ip,
                            "scope": f"Thất bại ({msg})",
                            "country": "-",
                            "city": "-",
                            "isp": "-",
                            "tag": "invalid"
                        })
            else:
                for ip in chunk:
                    results.append({
                        "ip": ip,
                        "scope": f"Lỗi HTTP {res.status_code}",
                        "country": "-",
                        "city": "-",
                        "isp": "-",
                        "tag": "invalid"
                    })
        except Exception as e:
            for ip in chunk:
                results.append({
                    "ip": ip,
                    "scope": "Lỗi kết nối",
                    "country": "-",
                    "city": "-",
                    "isp": "-",
                    "tag": "invalid"
                })

    # Map lại kết quả theo thứ tự ban đầu
    res_map = {r["ip"]: r for r in results}
    final_ordered = [res_map[ip] for ip in unique_ips if ip in res_map]

    return jsonify(final_ordered)


@app.route("/api/ocr", methods=["POST"])
def api_ocr():
    """
    Nhận file ảnh upload, dùng OCR để đọc text, trích xuất danh sách IPv4 hợp lệ.
    Trả về: { "ips": [...], "raw_text": "...", "count": N }
    """
    if "image" not in request.files:
        return jsonify({"error": "No image file uploaded. Use field name 'image'."}), 400

    file = request.files["image"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    # Kiểm tra định dạng file
    allowed_types = {"image/png", "image/jpeg", "image/jpg", "image/bmp", "image/webp", "image/gif", "image/tiff"}
    if file.content_type and file.content_type.lower() not in allowed_types:
        # Thử kiểm tra extension nếu content_type không rõ
        ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if ext not in {"png", "jpg", "jpeg", "bmp", "webp", "gif", "tiff"}:
            return jsonify({"error": f"Unsupported file type: {file.content_type}"}), 400

    try:
        import io
        try:
            from PIL import Image
        except ImportError:
            return jsonify({"error": "Thiếu thư viện Pillow. Chạy: pip install Pillow"}), 500

        try:
            import pytesseract
        except ImportError:
            return jsonify({"error": "Thiếu thư viện pytesseract. Chạy: pip install pytesseract"}), 500

        # Đọc ảnh từ memory
        img_bytes = file.read()
        img = Image.open(io.BytesIO(img_bytes))

        # Tối ưu ảnh cho OCR
        # Chuyển về RGB nếu cần (RGBA, P mode gây lỗi với một số engine)
        if img.mode not in ("RGB", "L"):
            img = img.convert("RGB")

        # Phóng to ảnh nếu quá nhỏ (OCR kém với ảnh nhỏ)
        w, h = img.size
        if w < 1200 or h < 900:
            scale = max(1200 / w, 900 / h, 1.5)
            new_w = int(w * scale)
            new_h = int(h * scale)
            img = img.resize((new_w, new_h), Image.LANCZOS)

        # Chạy OCR - config psm 6 (assume uniform block of text)
        ocr_config = r"--oem 3 --psm 6"
        raw_text = pytesseract.image_to_string(img, lang="eng", config=ocr_config)

        # Trích xuất IPv4 từ text OCR
        ip_pattern = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
        found_ips = []
        seen = set()
        for m in ip_pattern.finditer(raw_text):
            ip = m.group(0)
            if ip not in seen and _is_valid_ipv4(ip):
                found_ips.append(ip)
                seen.add(ip)

        return jsonify({
            "ips": found_ips,
            "count": len(found_ips),
            "raw_text": raw_text[:2000]  # Trả về tối đa 2000 ký tự để debug
        })

    except Exception as e:
        import traceback
        print(f"[OCR Error] {e}")
        print(traceback.format_exc())
        return jsonify({"error": f"OCR failed: {str(e)}"}), 500


@app.route("/api/check_malicious_bulk", methods=["POST"])
def api_check_malicious_bulk():
    body = request.get_json(silent=True) or {}
    ips = body.get("ips", [])
    if not isinstance(ips, list):
        return jsonify({"error": "ips must be a list"}), 400

    import concurrent.futures
    malicious = []

    def _check(ip):
        try:
            report = _run_enrichment(ip)
            # Include if there is any risk score > 0 or any malicious engines
            if report.risk.score > 0 or report.risk.level in ("CRITICAL", "HIGH", "MEDIUM"):
                reasons = [f.reason for f in report.risk.factors]
                return {
                    "ip": ip, 
                    "risk_level": report.risk.level, 
                    "score": report.risk.score,
                    "reasons": reasons
                }
        except Exception as e:
            print(f"Error checking {ip}: {e}")
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        for res in executor.map(_check, ips):
            if res:
                malicious.append(res)

    return jsonify({
        "malicious_ips": [r["ip"] for r in malicious], 
        "details": malicious
    })


if __name__ == "__main__":
    print("\n  SOC IOC Enrichment -- Web Interface")
    print("  http://127.0.0.1:5000\n")
    app.run(host="127.0.0.1", port=5000, debug=False)
