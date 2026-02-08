import os
import hashlib
import threading
import customtkinter as ctk
from tkinter import messagebox, filedialog, ttk
from PIL import Image, ImageTk
from colorama import Fore, Style, init
from pyfiglet import Figlet

init(autoreset=True)

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ================= BASE PATH ================= #
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# ================= BANNER ================= #
def print_banner():
    f = Figlet(font="slant")
    banner = f.renderText("Picklu")
    return banner

# ================= SAFE EXTENSIONS ================= #
SAFE_EXTENSIONS = (
    ".pdf", ".ppt", ".pptx", ".doc", ".docx",
    ".xls", ".xlsx", ".txt", ".csv",
    ".mp4", ".mp3", ".jpg", ".png", ".jpeg"
)

# ================= DANGER EXTENSIONS ================= #
DANGER_EXTENSIONS = (
    '.exe','.msi','.bat','.cmd','.com','.scr','.pif',
    '.jar','.apk','.app','.bin','.run',
    '.ps1','.vbs','.js','.jse','.wsf','.wsh',
    '.sh','.bash','.zsh','.ksh',
    '.py','.php','.pl','.rb','.lua',
    '.dll','.sys','.drv','.ocx','.so','.dylib',
    '.docm','.xlsm','.pptm','.dotm',
    '.zip','.rar','.7z','.tar','.gz','.bz2',
    '.xz','.iso','.img','.dmg',
    '.html','.htm','.xml','.svg','.swf',
    '.jsp','.asp','.aspx',
    '.lnk','.url','.desktop',
    '.torrent','.crx','.xpi','.deb','.rpm'
)

# ================= LOAD DATABASE ================= #
def load_keywords():
    keys = []
    path = os.path.join(BASE_DIR, "malware_keywords.txt")
    try:
        with open(path) as f:
            for line in f:
                keys.append(line.strip().lower())
    except:
        pass
    return keys

def load_hashes():
    db = {}
    path = os.path.join(BASE_DIR, "malware_hashes.txt")
    try:
        with open(path) as f:
            for line in f:
                if line.startswith("#") or not line.strip():
                    continue
                h, name = line.strip().split("|")
                db[h] = name
    except:
        pass
    return db

MALWARE_KEYWORDS = load_keywords()
KNOWN_HASHES = load_hashes()

# ================= USB DETECT ================= #
def list_usb_mounts():
    drives = []
    try:
        with open("/proc/mounts") as f:
            for line in f:
                if "/media/" in line or "/mnt/" in line:
                    drives.append(line.split()[1])
    except:
        pass
    return list(set(drives))

# ================= HASH ================= #
def get_hash(path):
    h = hashlib.sha256()
    try:
        with open(path,"rb") as f:
            h.update(f.read())
        return h.hexdigest()
    except:
        return None

# ================= FILE READ ================= #
def read_file(path):
    try:
        with open(path,"r",errors="ignore") as f:
            return f.read().lower()
    except:
        return ""

# ================= CHECKS ================= #
def keyword_scan(content):
    found = []
    for k in MALWARE_KEYWORDS:
        if k in content:
            found.append(k)
    return found

def hash_check(hashval):
    if hashval in KNOWN_HASHES:
        return KNOWN_HASHES[hashval]
    return None

def extension_check(name):
    name = name.lower()
    if name.endswith(SAFE_EXTENSIONS):
        return "SAFE"
    for ext in DANGER_EXTENSIONS:
        if name.endswith(ext):
            return "DANGER"
    return "UNKNOWN"

def heuristic_check(path):
    suspicious = []
    try:
        size = os.path.getsize(path)
        if size > 100 * 1024 * 1024:
            suspicious.append("Huge File")
        if os.access(path, os.X_OK):
            suspicious.append("Executable")
        if path.lower().endswith((".js",".vbs",".ps1",".sh")):
            suspicious.append("Script")
    except:
        pass
    return suspicious

# ================= DELETE ================= #
def ask_delete(path, log_callback, table_callback):
    result = messagebox.askyesno("Malware Detected!", f"Delete {path}? 😊")
    if result:
        try:
            os.remove(path)
            log_callback("✅ Deleted 🗑️\n")
            table_callback(path, "Deleted")
        except:
            log_callback("❌ Delete Failed 😔\n")
    else:
        log_callback("⚠️ Skipped\n")

# ================= SCANNER ================= #
def scan_usb(path, log_callback, progress_callback, table_callback, stop_event, start_from=0):
    log_callback(f"\nScanning: {path} 🔍\n")
    total_files = sum([len(files) for r, d, files in os.walk(path)])
    scanned = start_from
    file_count = 0
    for root, dirs, files in os.walk(path):
        for file in files:
            if stop_event.is_set():
                log_callback("Scan Stopped by User\n")
                return scanned  # Return progress for continuation
            full = os.path.join(root, file)
            file_count += 1
            if file_count <= start_from:
                continue  # Skip already scanned files
            try:
                hashv = get_hash(full)
                ext_status = extension_check(file)
                threat = False
                status = "Safe"
                color = "green"
                if ext_status == "SAFE":
                    status = "Safe"
                    color = "green"
                    # Skip further checks for safe extensions
                elif ext_status == "DANGER":
                    content = read_file(full)
                    keys = keyword_scan(content)
                    sig = hash_check(hashv)
                    heur = heuristic_check(full)
                    status = "Dangerous Extension 🔥"
                    color = "red"
                    threat = True
                    if keys:
                        status += " | Keywords ⚠️"
                    if sig:
                        status += f" | Signature: {sig}"
                    if heur:
                        status += f" | Behavior: {heur}"
                elif ext_status == "UNKNOWN":
                    content = read_file(full)
                    keys = keyword_scan(content)
                    sig = hash_check(hashv)
                    heur = heuristic_check(full)
                    status = "Unknown"
                    color = "yellow"
                    if keys:
                        status += " | Keywords ⚠️"
                        color = "red"
                        threat = True
                    if sig:
                        status += f" | Signature: {sig}"
                        color = "red"
                        threat = True
                    if heur:
                        status += f" | Behavior: {heur}"
                table_callback(full, status, hashv, color)
                if threat:
                    ask_delete(full, log_callback, lambda p, s: table_callback(p, s, hashv, color))
                log_callback(f"{file} - {status}\nSHA256: {hashv}\n")
            except Exception as e:
                log_callback(f"❌ Error: {e} 😵\n")
                table_callback(full, "Error", "", "yellow")
            scanned += 1
            progress_callback(scanned / total_files * 100)
    return scanned

# ================= CUTE & PROFESSIONAL GUI ================= #
class PickluFinalUpdatedGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Picklu - Cute Malware Scanner")
        self.root.geometry("1200x800")
        self.root.resizable(True, True)
        
        self.cute_font = ("Comic Sans MS", 12)
        self.scan_results = []
        self.stop_event = threading.Event()
        self.scan_progress = {}  # Track progress per USB for continuation
        self.filtered = False  # Track filter state
        
        # Sidebar
        self.sidebar = ctk.CTkFrame(root, width=200, corner_radius=10)
        self.sidebar.pack(side="left", fill="y", padx=10, pady=10)
        
        # Logo
        try:
            logo_img = Image.open("logo.png").resize((100, 100))
            self.logo = ImageTk.PhotoImage(logo_img)
            logo_label = ctk.CTkLabel(self.sidebar, image=self.logo, text="")
            logo_label.pack(pady=10)
        except:
            pass
        
        # Sidebar Buttons
        self.start_button = ctk.CTkButton(self.sidebar, text="Start Scan! 😄", command=self.start_scan, fg_color="green", hover_color="lightgreen", corner_radius=20)
        self.start_button.pack(pady=10)
        
        self.stop_button = ctk.CTkButton(self.sidebar, text="Stop Scan", command=self.stop_scan, fg_color="red", hover_color="darkred", corner_radius=20, state="disabled")
        self.stop_button.pack(pady=10)
        
        self.continue_button = ctk.CTkButton(self.sidebar, text="▶️ Continue Scan", command=self.continue_scan, fg_color="blue", hover_color="lightblue", corner_radius=20, state="disabled")
        self.continue_button.pack(pady=10)
        
        self.filter_button = ctk.CTkButton(self.sidebar, text="🔍 Filter Dangers", command=self.filter_dangers, fg_color="orange", corner_radius=20)
        self.filter_button.pack(pady=10)
        
        self.show_all_button = ctk.CTkButton(self.sidebar, text="📋 Show All Results", command=self.show_all_results, fg_color="purple", corner_radius=20)
        self.show_all_button.pack(pady=10)
        self.show_all_button.pack_forget()  # Hide initially
        
        self.export_button = ctk.CTkButton(self.sidebar, text="Export Results", command=self.export_results, fg_color="blue", corner_radius=20)
        self.export_button.pack(pady=10)
        
        self.exit_button = ctk.CTkButton(self.sidebar, text="Exit 😘", command=root.quit, fg_color="red", hover_color="pink", corner_radius=20)
        self.exit_button.pack(pady=10)
        
        # Main Frame
        self.main_frame = ctk.CTkFrame(root, corner_radius=10)
        self.main_frame.pack(side="right", fill="both", expand=True, padx=10, pady=10)
        
        # Tabs
        self.tabview = ctk.CTkTabview(self.main_frame)
        self.tabview.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Results Tab (Colorful Table)
        self.results_tab = self.tabview.add("📊 Scan Results")
        self.tree = ttk.Treeview(self.results_tab, columns=("File", "Path", "Status", "Hash"), show="headings", height=20)
        self.tree.heading("File", text="File Name")
        self.tree.heading("Path", text="Full Path 🗂️")
        self.tree.heading("Status", text="Status ✅")
        self.tree.heading("Hash", text="SHA256 ")
        self.tree.column("File", width=150)
        self.tree.column("Path", width=300)
        self.tree.column("Status", width=200)
        self.tree.column("Hash", width=250)
        self.tree.tag_configure("green", background="lightgreen", foreground="black")
        self.tree.tag_configure("red", background="lightcoral", foreground="black")
        self.tree.tag_configure("yellow", background="lightyellow", foreground="black")
        self.tree.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Logs Tab
        self.logs_tab = self.tabview.add("Detailed Logs")
        self.log_area = ctk.CTkTextbox(self.logs_tab, wrap="word", font=("Courier", 20))
        self.log_area.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Progress & Status
        self.progress = ctk.CTkProgressBar(self.main_frame, width=600, corner_radius=10)
        self.progress.pack(pady=10)
        self.progress.set(0)
        
        self.status_label = ctk.CTkLabel(self.main_frame, text="Ready to scan! 🐶", font=self.cute_font)
        self.status_label.pack(pady=5)
        
        # Spinner
        self.spinner = ctk.CTkLabel(self.main_frame, text="⏳", font=("Arial", 20))
        self.spinner.pack(pady=5)
        self.spinner.pack_forget()
        
        # Check databases
        if not MALWARE_KEYWORDS:
            messagebox.showwarning("Missing File", "⚠️ malware_keywords.txt missing 😟")
        if not KNOWN_HASHES:
            messagebox.showwarning("Missing File", "⚠️ malware_hashes.txt missing 😟")
    
    def log(self, message):
        self.log_area.insert("end", message)
        self.log_area.see("end")
    
    def update_progress(self, value):
        self.progress.set(value / 100)
        self.status_label.configure(text=f"Scanning... {int(value)}% complete!")
        if value >= 100 or self.stop_event.is_set():
            self.spinner.pack_forget()
            self.stop_button.configure(state="disabled")
            if self.stop_event.is_set():
                self.continue_button.configure(state="normal")
    
    def add_to_table(self, path, status, hashv, color="green"):
        file_name = os.path.basename(path)
        self.tree.insert("", "end", values=(file_name, path, status, hashv), tags=(color,))
        self.scan_results.append((file_name, path, status, hashv, color))
    
    def filter_dangers(self):
        self.filtered = True
        self.filter_button.pack_forget()
        self.show_all_button.pack(pady=10)
        for item in self.tree.get_children():
            self.tree.delete(item)
        for res in self.scan_results:
            if res[4] == "red":
                self.tree.insert("", "end", values=res[:4], tags=(res[4],))
    
    def show_all_results(self):
        self.filtered = False
        self.show_all_button.pack_forget()
        self.filter_button.pack(pady=10)
        for item in self.tree.get_children():
            self.tree.delete(item)
        for res in self.scan_results:
            self.tree.insert("", "end", values=res[:4], tags=(res[4],))
    
    def export_results(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, "w") as f:
                f.write("File Name\tPath\tStatus\tHash\n")
                for res in self.scan_results:
                    f.write("\t".join(res[:4]) + "\n")
            messagebox.showinfo("Exported", "Results exported!")
    
    def start_scan(self):
        usb_list = list_usb_mounts()
        if not usb_list:
            messagebox.showerror("No USB Found 😢", "⚠️ No USB drives detected. Plug one in!")
            return
        self.stop_event.clear()
        self.scan_progress = {usb: 0 for usb in usb_list}  # Reset progress
        self.log("🔍 Searching USB Drives... 🕵️‍♀️\n")
        self.progress.set(0)
        self.spinner.pack(pady=5)
        self.stop_button.configure(state="normal")
        self.continue_button.configure(state="disabled")
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.scan_results = []
        for usb in usb_list:
            threading.Thread(target=self.scan_single_usb, args=(usb,)).start()
        self.status_label.configure(text="Scan Completed! 🏆")
    
    def scan_single_usb(self, usb):
        progress = scan_usb(usb, self.log, self.update_progress, self.add_to_table, self.stop_event, self.scan_progress[usb])
        self.scan_progress[usb] = progress
    
    def stop_scan(self):
        self.stop_event.set()
        self.status_label.configure(text="Scan Stopped! 😌")
        self.stop_button.configure(state="disabled")
    
    def continue_scan(self):
        usb_list = list_usb_mounts()
        if not usb_list:
            messagebox.showerror("No USB Found 😢", "⚠️ No USB drives detected. Plug one in!")
            return
        self.stop_event.clear()
        self.log("▶️ Continuing Scan... \n")
        self.spinner.pack(pady=5)
        self.stop_button.configure(state="normal")
        self.continue_button.configure(state="disabled")
        for usb in usb_list:
            threading.Thread(target=self.scan_single_usb, args=(usb,)).start()
        self.status_label.configure(text="Scan Continued! 🏆")

# ================= MAIN ================= #
if __name__ == "__main__":
    root = ctk.CTk()
    app = PickluFinalUpdatedGUI(root)
    root.mainloop()
