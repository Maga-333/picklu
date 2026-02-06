# 🧠 Picklu - USB Malware & Forensics Scanner

Picklu is a smart Python-based offline USB security tool that:

- 🔌 Automatically detects mounted USB drives  
- 🛡️ Scans files using extensions, keywords, hashes, and behavior analysis  
- 📄 Displays detected file extensions and matched keywords  
- 🔍 Calculates SHA256 hash for every file  
- 🧹 Asks before deleting malicious files  
- 📁 Categorizes files into Safe ✅, Suspicious ⚠️, and Dangerous ❌  
- 💻 Works fully offline without internet  
- ⚡ Lightweight, portable, and fast  

---

# 🔧 How to Install

## 1. Clone the repository

git clone https://github.com/Maga-333/Picklu.git

## 2. Navigate into the project directory

cd Picklu

## 3. Create a Python virtual environment

python3 -m venv .venv

## 4. Activate the virtual environment

source .venv/bin/activate

## 5. Install all required libraries

pip install -r requirements.txt

---

# 🧪 How to Use Picklu

## 6. Insert the USB drive and identify it

lsblk

    Look for the USB device, such as /dev/sdb1

## 7. Mount the USB (if not auto-mounted)

sudo mkdir -p /media/card

sudo mount /dev/sdb1 /media/card

    ⚠️ Replace sdX1 with your actual USB name.

## 8. Run the Picklu scanner

python3 picklu.py

    The tool will:

        Scan all files in the USB drive

        Display SHA256 hash for each file

        Show detected extensions and keywords

        Identify suspicious and dangerous files

        Ask confirmation before deleting threats

        Display colorful output in terminal

## 9. To deactivate the virtual environment

deactivate

---

# 📊 Detection Methods Used

Picklu analyzes files using:

    ✔ File Extension Scanning
    ✔ Malware Keyword Detection
    ✔ Known Hash Signature Matching
    ✔ Heuristic Behavior Analysis
    ✔ Executable Permission Check

---

# 🖥️ Sample Output

---------------------------
📄 virus_sample.exe  
🔐 SHA256: 8a3f9b...

🚨 Dangerous Extension: .exe  
🚨 Keywords Found: payload, shellcode  

⚠️ MALWARE DETECTED  
Delete file? (yes/no/exit): yes  
✅ Deleted  

---

# ⚠️ Disclaimer

Picklu is developed for educational and research purposes only.

It is intended for:

    ✔ Cybersecurity learning  
    ✔ Academic projects  
    ✔ USB malware analysis  

Do not use this tool for illegal activities.

---

👨‍💻 Developed 💛 by LNT  
