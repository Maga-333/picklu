import os
import time
import hashlib
from colorama import Fore, Style, init
from pyfiglet import Figlet
from colorama import Fore, Style, init
import shutil

import getpass
AUTHORIZED_USER = "superstar"

current_user = getpass.getuser()
if current_user != AUTHORIZED_USER:
    print(f"\n🚫 Access Denied! Only {AUTHORIZED_USER} can run this tool.")
    exit()

def print_banner():
    f = Figlet(font='slant')  # Same as TrackTrack
    banner = f.renderText("Picklu")  # Banner text

    # Get terminal width
    cols = shutil.get_terminal_size().columns

    # Line-by-line coloring (Zphozher style)
    colors = [Fore.CYAN, Fore.MAGENTA, Fore.YELLOW, Fore.GREEN, Fore.BLUE, Fore.RED]
    lines = banner.split('\n')

    for i, line in enumerate(lines):
        color = colors[i % len(colors)]
        print(color + line)  # Centered output

    # Subtitle – left aligned, like TrackTrack
    print(Fore.LIGHTWHITE_EX + Style.BRIGHT + "Tool: USB Forensics Tool\n")

init(autoreset=True)

def list_usb_mounts():
    print(Fore.CYAN + "\n🔍 Scanning for USB drives...")
    usb_drives = []
    with open('/proc/mounts', 'r') as f:
        for line in f:
            if '/media/' in line or '/run/media/' in line or '/mnt/' in line:
                parts = line.split()
                usb_drives.append(parts[1])
    return list(set(usb_drives))

def hash_file(filepath):
    hasher = hashlib.sha256()
    try:
        with open(filepath, 'rb') as afile:
            buf = afile.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except:
        return "Permission Denied"

def scan_files(path):
    print(Fore.GREEN + f"\n📂 Scanning Files in: {path}")
    for root, dirs, files in os.walk(path):
        for file in files:
            # Filter: only error-related files
            if file.lower().endswith(error_extensions) or 'error' in file.lower():
                full_path = os.path.join(root, file)
                try:
                    size = os.path.getsize(full_path)
                    created = time.ctime(os.path.getctime(full_path))
                    modified = time.ctime(os.path.getmtime(full_path))
                    hashval = hash_file(full_path)

                    print(Fore.YELLOW + f"\n📝 File: {file}")
                    print(Fore.BLUE + f"   📍 Path: {full_path}")
                    print(Fore.MAGENTA + f"   📏 Size: {size} bytes")
                    print(Fore.CYAN + f"   🕓 Created: {created}")
                    print(Fore.CYAN + f"   🔧 Modified: {modified}")
                    print(Fore.RED + f"   🧪 SHA256: {hashval}")
                except:
                    print(Fore.RED + f"\n❌ Cannot access: {full_path}")

error_extensions = (
    '.log', '.err', '.error', '.trace', '.crash', '.dmp', '.core', '.stacktrace',
    '.out', '.fail', '.stderr', '.stdout', '.bak', '.tmp', '.mdmp', '.hdmp', '.rpt',
    '.dump', '.trc', '.panic', '.fatal', '.debug', '.ftrace', '.record', '.diag',
    '.old', '.prev', '.report', '.bug', '.exception', '.syslog', '.journal',
    '.txt', '.cfg', '.ini', '.conf', '.sav', '.state', '.issue', '.sym', '.symbol',
    '.backtrace', '.traceback', '.logfile', '.minidump', '.oom', '.coredump', 
    '.failures', '.recovery', '.repair'
)

if __name__ == "__main__":
    print_banner()
    usb_list = list_usb_mounts()
    if not usb_list:
        print(Fore.RED + "⚠️ No USB drive found. Plug one in!")
    else:
        for usb in usb_list:
            scan_files(usb)
