import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import threading
import requests
import re
import csv

BATCH_API_URL = "http://ip-api.com/batch?fields=status,message,country,countryCode,city,isp,query"

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

class IPCheckerApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("IP Geo Checker - Kiểm tra IP Nước Ngoài")
        self.geometry("900x600")
        self.minsize(750, 450)

        self._build_ui()

    def _build_ui(self):
        # Khung trên: Nhập danh sách IP
        input_frame = ttk.LabelFrame(self, text=" Danh sách IP cần check (mỗi dòng hoặc cách nhau dấu phẩy/khoảng trắng) ")
        input_frame.pack(fill=tk.BOTH, expand=False, padx=10, pady=8)

        self.txt_ips = tk.Text(input_frame, height=6, wrap=tk.WORD, font=("Consolas", 10))
        self.txt_ips.pack(fill=tk.BOTH, expand=True, padx=8, pady=6)
        
        # IP mẫu
        sample_ips = "8.8.8.8\n1.1.1.1\n113.161.72.1\n192.168.1.1\n203.162.0.181"
        self.txt_ips.insert(tk.END, sample_ips)

        # Khung điều khiển
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, padx=10, pady=4)

        self.btn_check = ttk.Button(btn_frame, text="▶ Kiểm tra", command=self.start_checking)
        self.btn_check.pack(side=tk.LEFT, padx=(0, 6))

        self.btn_clear = ttk.Button(btn_frame, text="Xóa kết quả", command=self.clear_results)
        self.btn_clear.pack(side=tk.LEFT, padx=6)

        self.btn_export = ttk.Button(btn_frame, text="Xuất CSV", command=self.export_csv)
        self.btn_export.pack(side=tk.LEFT, padx=6)
        
        self.btn_malicious = ttk.Button(btn_frame, text="Check Độc Hại", command=self.check_malicious)
        self.btn_malicious.pack(side=tk.LEFT, padx=6)

        self.var_exclude_google = tk.BooleanVar(value=True)
        self.chk_google = ttk.Checkbutton(btn_frame, text="Loại trừ IP Google", variable=self.var_exclude_google)
        self.chk_google.pack(side=tk.LEFT, padx=6)

        self.lbl_status = ttk.Label(btn_frame, text="Sẵn sàng", font=("Segoe UI", 9, "italic"))
        self.lbl_status.pack(side=tk.RIGHT, padx=5)

        # Khung dưới: Bảng hiển thị kết quả
        table_frame = ttk.LabelFrame(self, text=" Kết quả kiểm tra (Chỉ hiển thị IP Nước Ngoài) ")
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=8)

        cols = ("ip", "status", "country", "city", "isp")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings")

        self.tree.heading("ip", text="Địa chỉ IP")
        self.tree.heading("status", text="Loại IP (Phạm vi)")
        self.tree.heading("country", text="Quốc gia")
        self.tree.heading("city", text="Thành phố")
        self.tree.heading("isp", text="Nhà mạng / ISP")

        self.tree.column("ip", width=140, anchor=tk.CENTER)
        self.tree.column("status", width=160, anchor=tk.CENTER)
        self.tree.column("country", width=160)
        self.tree.column("city", width=140)
        self.tree.column("isp", width=240)

        # Tag màu sắc trực quan
        self.tree.tag_configure("foreign", background="#FDE8E8", foreground="#9C1C1C")     # Đỏ nhạt: Nước ngoài
        self.tree.tag_configure("domestic", background="#EAF5EA", foreground="#1E4620")    # Xanh nhạt: Việt Nam
        self.tree.tag_configure("private", background="#FFFBEA", foreground="#744210")     # Vàng nhạt: Nội bộ
        self.tree.tag_configure("invalid", background="#F3F4F6", foreground="#6B7280")     # Xám: Không hợp lệ

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscroll=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(6, 0), pady=6)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=6, padx=(0, 6))

    def parse_ips(self):
        raw = self.txt_ips.get("1.0", tk.END)
        # Bắt địa chỉ IPv4
        matches = re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", raw)
        # Validate từng octet (0-255) để loại IP không hợp lệ như 999.999.999.999
        valid = [ip for ip in matches if _is_valid_ipv4(ip)]
        return list(dict.fromkeys(valid))  # Giữ thứ tự và loại bỏ trùng lặp

    def start_checking(self):
        ips = self.parse_ips()
        if not ips:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập ít nhất một địa chỉ IPv4 hợp lệ.")
            return

        self.btn_check.config(state=tk.DISABLED)
        self.lbl_status.config(text=f"Đang phân tích {len(ips)} IP...")
        self.tree.delete(*self.tree.get_children())

        # Xử lý trong thread riêng để không gây đơ giao diện
        thread = threading.Thread(target=self._process_ips_thread, args=(ips,), daemon=True)
        thread.start()

    def _process_ips_thread(self, ips):
        to_lookup = []

        for ip in ips:
            if is_private_ip(ip):
                pass  # Không hiển thị IP nội bộ (chỉ hiển thị IP Nước ngoài)
            else:
                to_lookup.append(ip)

        # Gọi API theo từng block tối đa 100 IP (giới hạn của ip-api batch)
        chunk_size = 100
        for i in range(0, len(to_lookup), chunk_size):
            chunk = to_lookup[i:i + chunk_size]
            try:
                res = requests.post(BATCH_API_URL, json=chunk, timeout=12)
                if res.status_code == 200:
                    data = res.json()
                    for item in data:
                        ip = item.get("query", "")
                        if item.get("status") == "success":
                            country_code = (item.get("countryCode") or "").strip().upper()
                            country = item.get("country") or "-"
                            city = item.get("city") or "-"
                            isp = item.get("isp") or "-"

                            # countryCode rỗng → API không nhận diện → bỏ qua (không phải nước ngoài)
                            if not country_code:
                                pass  # Bỏ qua IP không xác định
                            elif country_code == "VN":
                                pass  # Bỏ qua IP Việt Nam
                            else:
                                # Chỉ hiển thị IP Nước ngoài
                                scope = f"NƯỚC NGOÀI ({country_code})"
                                tag = "foreign"
                                if self.var_exclude_google.get() and isp and "google" in isp.lower():
                                    pass  # Loại trừ IP Google
                                else:
                                    self._insert_row((ip, scope, country, city, isp, tag))
                        else:
                            pass  # Không hiển thị lỗi
                else:
                    pass
            except Exception as e:
                pass

        self.after(0, self._finish_checking)

    def _insert_row(self, row_data):
        # row_data = (ip, scope, country, city, isp, tag)
        self.after(0, lambda: self.tree.insert("", tk.END, values=row_data[:5], tags=(row_data[5],)))

    def _finish_checking(self):
        self.btn_check.config(state=tk.NORMAL)
        self.lbl_status.config(text="Kiểm tra hoàn tất (Chỉ hiển thị IP Nước Ngoài).")

    def check_malicious(self):
        rows = self.tree.get_children()
        if not rows:
            messagebox.showinfo("Thông báo", "Không có IP Nước ngoài nào để kiểm tra.")
            return

        ips = [self.tree.item(r)["values"][0] for r in rows]
        self.btn_malicious.config(state=tk.DISABLED)
        self.lbl_status.config(text=f"Đang kiểm tra mức độ độc hại cho {len(ips)} IP...")
        
        thread = threading.Thread(target=self._check_malicious_thread, args=(ips,), daemon=True)
        thread.start()

    def _check_malicious_thread(self, ips):
        try:
            res = requests.post("http://127.0.0.1:5000/api/check_malicious_bulk", json={"ips": ips}, timeout=60)
            if res.status_code == 200:
                data = res.json()
                details = data.get("details", [])
                self.after(0, lambda: self._show_malicious_result(details))
            else:
                self.after(0, lambda: messagebox.showerror("Lỗi", f"Lỗi HTTP {res.status_code}"))
        except Exception as e:
            self.after(0, lambda: messagebox.showerror("Lỗi", f"Không thể kết nối đến server backend: {str(e)}"))
        finally:
            self.after(0, lambda: self.btn_malicious.config(state=tk.NORMAL))
            self.after(0, lambda: self.lbl_status.config(text="Kiểm tra độc hại hoàn tất."))

    def _show_malicious_result(self, details):
        if not details:
            messagebox.showinfo("Kết quả", "Không phát hiện IP độc hại nào trong danh sách!")
            return
            
        top = tk.Toplevel(self)
        top.title("Danh sách IP Độc Hại")
        top.geometry("600x400")
        
        lbl = ttk.Label(top, text=f"Phát hiện {len(details)} IP có dấu hiệu rủi ro:")
        lbl.pack(padx=10, pady=5, anchor="w")
        
        txt = tk.Text(top, wrap=tk.WORD, font=("Consolas", 10))
        txt.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        output_lines = []
        malicious_ips = []
        for item in details:
            malicious_ips.append(item['ip'])
            output_lines.append(f"[IP] {item['ip']}")
            output_lines.append(f"- Mức độ: {item['risk_level']} (Score: {item['score']})")
            if item.get("reasons"):
                output_lines.append(f"- Dấu hiệu: {' | '.join(item['reasons'])}")
            output_lines.append("")
            
        full_text = "\n".join(output_lines).strip()
        txt.insert(tk.END, full_text)
        txt.config(state=tk.DISABLED)
        
        def copy_to_clipboard():
            if not malicious_ips: return
            self.clipboard_clear()
            self.clipboard_append("\n".join(malicious_ips))
            messagebox.showinfo("Thành công", "Đã copy danh sách IP độc hại (chỉ copy IP)!")
            
        btn = ttk.Button(top, text="Copy Danh Sách IP", command=copy_to_clipboard)
        btn.pack(pady=10)

    def clear_results(self):
        self.tree.delete(*self.tree.get_children())
        self.lbl_status.config(text="Đã xóa kết quả.")

    def export_csv(self):
        rows = self.tree.get_children()
        if not rows:
            messagebox.showinfo("Thông báo", "Không có dữ liệu để xuất.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv")],
            title="Lưu kết quả kiểm tra IP"
        )
        if not path:
            return

        try:
            with open(path, mode="w", newline="", encoding="utf-8-sig") as f:
                writer = csv.writer(f)
                writer.writerow(["IP", "Trạng thái", "Quốc gia", "Thành phố", "ISP"])
                for r in rows:
                    writer.writerow(self.tree.item(r)["values"])
            messagebox.showinfo("Thành công", f"Đã xuất file tại:\n{path}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Không thể ghi file: {str(e)}")

if __name__ == "__main__":
    app = IPCheckerApp()
    app.mainloop()