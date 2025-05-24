import os
import sys
import subprocess
import re
import logging
import time
from datetime import datetime

LOG_FILE = "monitor_bot.log"

# Log settings
logging.basicConfig(
    filename=LOG_FILE,
    filemode='a',
    level=logging.INFO,
    format='[%(asctime)s] [%(levelname)s] %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def check_root():
    if os.geteuid() != 0:
        print("[-] Root olarak çalıştırılmalı.")
        logging.error("Root yetkisi olmadan çalıştırıldı.")
        sys.exit(1)

def get_wireless_interfaces():
    try:
        output = subprocess.check_output("iw dev", shell=True).decode()
        interfaces = re.findall(r'Interface\s+(\w+)', output)
        return interfaces
    except subprocess.CalledProcessError:
        print("[-] iw dev komutu başarısız.")
        logging.error("iw dev komutu başarısız.")
        sys.exit(1)

def select_interface(interfaces):
    print("\n[*] Kablosuz arayüzler:")
    for i, iface in enumerate(interfaces, 1):
        print(f"{i}. {iface}")
    while True:
        try:
            choice = int(input("\nArayüz seçimi (numara): "))
            if 1 <= choice <= len(interfaces):
                return interfaces[choice - 1]
            else:
                print("[-] Geçersiz seçim.")
        except ValueError:
            print("[-] Sayı giriniz.")

def enable_monitor_mode(interface):
    print(f"[*] {interface} için monitor mod açılıyor (airmon-ng)...")
    try:
        subprocess.run(f"airmon-ng start {interface}", shell=True, check=True)
        mon_iface = detect_monitor_interface(interface)
        if mon_iface:
            print(f"[+] Monitor mod aktif: {mon_iface}")
            logging.info(f"{interface} → {mon_iface} monitor moduna alındı.")
            return mon_iface
        else:
            print("[-] Monitor mod arayüzü bulunamadı.")
            logging.error(f"{interface} monitor moduna alınamadı.")
            return None
    except subprocess.CalledProcessError:
        print("[-] airmon-ng başarısız.")
        logging.error("airmon-ng start başarısız.")
        return None

def disable_monitor_mode(mon_iface):
    print(f"[*] {mon_iface} monitor mod kapatılıyor (airmon-ng)...")
    try:
        subprocess.run(f"airmon-ng stop {mon_iface}", shell=True, check=True)
        print(f"[+] Monitor mod kapatıldı: {mon_iface}")
        logging.info(f"{mon_iface} monitor mod kapatıldı.")
    except subprocess.CalledProcessError:
        print("[-] Monitor mod kapatılamadı.")
        logging.error(f"{mon_iface} monitor mod kapatılamadı.")

def detect_monitor_interface(original_iface):
    try:
        output = subprocess.check_output("iw dev", shell=True).decode()
        interfaces = re.findall(r'Interface\s+(\w+)', output)
        for iface in interfaces:
            if iface.startswith(original_iface) and iface != original_iface:
                return iface
        return None
    except subprocess.CalledProcessError:
        return None

def check_interface_mode(interface):
    try:
        output = subprocess.check_output(f"iwconfig {interface}", shell=True).decode()
        if "Monitor" in output:
            print(f"[✓] {interface} monitor modda.")
            logging.info(f"{interface} monitor modda.")
        elif "Managed" in output:
            print(f"[-] {interface} normal modda.")
            logging.info(f"{interface} normal modda.")
        else:
            print(f"[?] {interface} mod tespit edilemedi.")
            logging.warning(f"{interface} mod durumu bilinmiyor.")
    except subprocess.CalledProcessError:
        print("[-] iwconfig komutu başarısız.")
        logging.error("iwconfig başarısız.")

def run_airodump_scan(interface, duration=20):
    print(f"[*] {interface} ile {duration} saniyelik ağ taraması başlatılıyor...")
    output_file = "scan_results"
    try:
        cmd = f"airodump-ng --write {output_file} --write-interval 1 --output-format csv {interface}"
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(duration)
        proc.terminate()
        time.sleep(1)

        csv_file = f"{output_file}-01.csv"
        if os.path.exists(csv_file):
            with open(csv_file, "r") as f:
                lines = f.readlines()
                logging.info(f"Ağ taraması ({interface}) sonuçları:")
                for line in lines:
                    if "," in line and "Station MAC" not in line:
                        logging.info("    " + line.strip())
            print("[✓] Tarama tamamlandı. Log dosyasına yazıldı.")
            os.remove(csv_file)
        else:
            print("[-] Tarama sonucu bulunamadı.")
            logging.warning("airodump-ng çıktı dosyası yok.")
    except Exception as e:
        print("[-] Tarama sırasında hata oluştu.")
        logging.error(f"Ağ taraması hatası: {e}")

def main():
    check_root()
    interfaces = get_wireless_interfaces()
    iface = select_interface(interfaces)
    logging.info(f"Kullanıcı {iface} arayüzünü seçti.")

    print("\nİşlem Seç:")
    print("1. Monitor modunu AÇ (airmon-ng)")
    print("2. Monitor modunu KAPAT (airmon-ng)")
    print("3. Arayüz modunu kontrol et")
    print("4. Ağ taraması yap (airodump-ng, monitor mod gerekli)")
    choice = input("Seçimin (1/2/3/4): ").strip()

    if choice == "1":
        mon_iface = enable_monitor_mode(iface)
        if mon_iface:
            print(f"[✓] {mon_iface} artık hazır.")
    elif choice == "2":
        mon_iface = input("Monitor modda olan arayüz ismi (örnek: wlan0mon): ").strip()
        disable_monitor_mode(mon_iface)
    elif choice == "3":
        check_interface_mode(iface)
    elif choice == "4":
        scan_time = input("Tarama süresi (saniye): ").strip()
        try:
            seconds = int(scan_time)
            run_airodump_scan(iface, seconds)
        except ValueError:
            print("[-] Geçerli sayı girin.")
    else:
        print("[-] Geçersiz seçim.")
        logging.warning("Geçersiz işlem seçimi.")

if __name__ == "__main__":
    main()
