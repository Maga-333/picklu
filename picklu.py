import os
import hashlib
import shutil

from colorama import Fore, Style, init
from pyfiglet import Figlet

init(autoreset=True)

# ================= BASE PATH ================= #

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ================= BANNER ================= #

def print_banner():

    f = Figlet(font="slant")
    banner = f.renderText("Picklu")

    colors = [
        Fore.CYAN, Fore.MAGENTA,
        Fore.YELLOW, Fore.GREEN,
        Fore.BLUE, Fore.RED
    ]

    for i, line in enumerate(banner.split("\n")):
        print(colors[i % len(colors)] + line)

    print(Fore.WHITE + Style.BRIGHT +
          "Offline USB Malware & Forensics Scanner\n")



# ================= SAFE EXTENSIONS ================= #

SAFE_EXTENSIONS = (
    ".pdf", ".ppt", ".pptx", ".doc", ".docx",
    ".xls", ".xlsx", ".txt", ".csv",
    ".mp4", ".mp3", ".jpg", ".png", ".jpeg"
)



# ================= DANGER EXTENSIONS ================= #

DANGER_EXTENSIONS = (

    # Executables
    '.exe','.msi','.bat','.cmd','.com','.scr','.pif',
    '.jar','.apk','.app','.bin','.run',

    # Scripts
    '.ps1','.vbs','.js','.jse','.wsf','.wsh',
    '.sh','.bash','.zsh','.ksh',
    '.py','.php','.pl','.rb','.lua',

    # System / DLL
    '.dll','.sys','.drv','.ocx','.so','.dylib',

    # Office Macros
    '.docm','.xlsm','.pptm','.dotm',

    # Archives
    '.zip','.rar','.7z','.tar','.gz','.bz2',
    '.xz','.iso','.img','.dmg',

    # Web
    '.html','.htm','.xml','.svg','.swf',
    '.jsp','.asp','.aspx',

    # Shortcuts
    '.lnk','.url','.desktop',

    # Others
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
        print(Fore.RED + "⚠️ malware_keywords.txt missing")

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
        print(Fore.RED + "⚠️ malware_hashes.txt missing")

    return db



MALWARE_KEYWORDS = load_keywords()
KNOWN_HASHES = load_hashes()



# ================= USB DETECT ================= #

def list_usb_mounts():

    print(Fore.CYAN + "🔍 Searching USB Drives...")

    drives = []

    with open("/proc/mounts") as f:

        for line in f:
            if "/media/" in line or "/mnt/" in line:
                drives.append(line.split()[1])

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

def ask_delete(path):

    while True:

        print(Fore.RED + "\n⚠️ MALWARE DETECTED")

        choice = input(
            Fore.YELLOW +
            "Delete file? (yes/no/exit): "
        ).strip().lower()


        if choice == "yes":

            try:
                os.remove(path)
                print(Fore.GREEN + "✅ Deleted")
            except:
                print(Fore.RED + "❌ Delete Failed")

            break


        elif choice == "no":

            print(Fore.YELLOW + "⚠️ Skipped")
            break


        elif choice == "exit":

            print(Fore.MAGENTA + "🛑 Scan Stopped")
            exit()


        else:

            print(Fore.CYAN + "❗ Type: yes / no / exit")



# ================= SCANNER ================= #

def scan_usb(path):

    print(Fore.GREEN + f"\n📂 Scanning: {path}")

    for root,dirs,files in os.walk(path):

        for file in files:

            full = os.path.join(root,file)

            try:

                print(Fore.BLUE + "\n---------------------------")
                print(Fore.YELLOW + "📄", file)

                hashv = get_hash(full)

                print(Fore.CYAN + "🔐 SHA256:", hashv)


                content = read_file(full)

                keys = keyword_scan(content)

                sig = hash_check(hashv)

                ext_status = extension_check(file)

                heur = heuristic_check(full)


                threat = False


                # ===== RESULTS ===== #

                if ext_status == "SAFE":
                    print(Fore.GREEN + "✅ Trusted File (Skipped)")
                    continue


                if ext_status == "DANGER":
                    print(Fore.RED + "🚨 Dangerous Extension")
                    threat = True


                if keys:
                    print(Fore.RED + "🚨 Keywords:", keys[:10])
                    threat = True


                if sig:
                    print(Fore.RED + "🚨 Signature:", sig)
                    threat = True


                if heur:
                    print(Fore.YELLOW + "⚠️ Behavior:", heur)


                if threat:

                    ask_delete(full)

                else:

                    print(Fore.GREEN + "✅ Safe File")


            except Exception as e:

                print(Fore.RED + "❌ Error:", e)



# ================= MAIN ================= #

if __name__ == "__main__":

    print_banner()

    usb_list = list_usb_mounts()


    if not usb_list:

        print(Fore.RED + "⚠️ No USB Found")

    else:

        for usb in usb_list:

            scan_usb(usb)


        print(Fore.GREEN + "\n🎯 Scan Completed")
