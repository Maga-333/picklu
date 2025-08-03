# 🧠 Picklu - USB Forensics & Error File Scanner

Picklu is a smart Python-based USB security tool that:

- 🔌 Detects and scans mounted USB drives  
- 🛡️ Identifies files containing hacker code or suspicious patterns  
- 🧹 Automatically removes error or malicious files  
- 📁 Categorizes files into Safe ✅ and Dangerous ❌  
- 🧾 Logs all activity with clear timestamps  
- 💻 Lightweight, portable, and fast  

---

# 🔧 How to Install

## 1. Clone the repository
```bash
git clone https://github.com/Maga-333/Picklu.git

2. Navigate into the project directory

cd Picklu

3. Create a Python virtual environment

python3 -m venv .venv

4. Activate the virtual environment

source .venv/bin/activate

5. Install all required libraries

pip install -r requirements.txt

🧪 How to Use Picklu
6. Insert the USB drive and identify it

lsblk

    Look for the USB device, such as /dev/sdb1

7. Mount the USB (if not auto-mounted)

sudo mkdir -p /mnt/usb
sudo mount /dev/sdX1 /mnt/usb

    ⚠️ Replace sdX1 with your actual USB name.

8. Run the Picklu scanner

python3 picklu.py

    The tool will:

        Scan files in the USB

        Remove dangerous ones

        Save logs to the logs/ folder

9. To deactivate the virtual environment

deactivate

👨‍💻 Developed 💚 by LNT
