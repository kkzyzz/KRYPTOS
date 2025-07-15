import json
import os
import re
import hashlib
from cryptography.fernet import Fernet
from colorama import init, Fore
import pyperclip
from datetime import datetime, timedelta
from pykeepass import PyKeePass, create_database
from encryption import Encryption
import requests
import zxcvbn

class PasswordManager:
    def __init__(self):
        self.encryption = Encryption()
        self.master_password = None
        self.security_score = 0
        
    def calculate_password_strength(self, password):
        result = zxcvbn.zxcvbn(password)
        return {
            'score': result['score'],  # 0-4 arası
            'crack_time': result['crack_times_display']['offline_fast_hashing_1e10_per_second'],
            'feedback': result['feedback']['warning'] if result['feedback']['warning'] else "Güçlü şifre",
            'suggestions': result['feedback']['suggestions']
        }
        
    def check_password_breach(self, password):
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix, suffix = sha1_hash[:5], sha1_hash[5:]
        
        try:
            response = requests.get(f'https://api.pwnedpasswords.com/range/{prefix}')
            if response.status_code == 200:
                hashes = (line.split(':') for line in response.text.splitlines())
                for hash_suffix, count in hashes:
                    if hash_suffix == suffix:
                        return int(count)
            return 0
        except:
            return -1  # API hatası
            
    def calculate_overall_security_score(self):
        total_score = 0
        total_passwords = 0
        weak_passwords = []
        breached_passwords = []
        
        for service in self.list_services():
            info = self.get_password_info(service)
            if info:
                password = info['password']
                strength = self.calculate_password_strength(password)
                breach_count = self.check_password_breach(password)
                
                # Skor hesaplama (0-100 arası)
                password_score = (strength['score'] + 1) * 20  # 0-100 arasına çevir
                
                # Sızıntı kontrolü
                if breach_count > 0:
                    password_score = max(0, password_score - 50)  # Sızıntı varsa 50 puan düş
                    breached_passwords.append({
                        'service': service,
                        'breach_count': breach_count
                    })
                
                # Zayıf şifre kontrolü
                if strength['score'] < 2:
                    weak_passwords.append({
                        'service': service,
                        'strength': strength
                    })
                
                total_score += password_score
                total_passwords += 1
        
        if total_passwords > 0:
            self.security_score = total_score / total_passwords
        else:
            self.security_score = 0
            
        return {
            'overall_score': self.security_score,
            'weak_passwords': weak_passwords,
            'breached_passwords': breached_passwords,
            'total_passwords': total_passwords
        }
        
    def generate_secure_password(self, length=16, include_uppercase=True, include_lowercase=True,
                               include_numbers=True, include_special=True):
        import string
        import random
        
        chars = ''
        if include_uppercase:
            chars += string.ascii_uppercase
        if include_lowercase:
            chars += string.ascii_lowercase
        if include_numbers:
            chars += string.digits
        if include_special:
            chars += string.punctuation
            
        if not chars:
            chars = string.ascii_letters + string.digits + string.punctuation
            
        while True:
            password = ''.join(random.choice(chars) for _ in range(length))
            strength = self.calculate_password_strength(password)
            if strength['score'] >= 3:  # En az "güçlü" seviyesinde
                return password
        
    def set_master_password(self, password):
        self.master_password = password
        if not self.encryption.open_database(password):
            self.encryption.create_database(password)
            
    def add_password(self, service, password, expires_in_days=90):
        if not self.master_password:
            return False, "Ana şifre ayarlanmamış!"
            
        if self.encryption.get_entry(service):
            return False, "Bu servis için zaten bir şifre var!"
            
        if self.encryption.add_entry(service, password, expires_in_days=expires_in_days):
            return True, "Şifre başarıyla eklendi!"
        return False, "Şifre eklenirken bir hata oluştu!"
        
    def get_password(self, service):
        if not self.master_password:
            return False, None
            
        entry = self.encryption.get_entry(service)
        if entry:
            return True, entry.password
        return False, None
        
    def delete_password(self, service):
        if not self.master_password:
            return False, "Ana şifre ayarlanmamış!"
            
        if self.encryption.delete_entry(service):
            return True, "Şifre başarıyla silindi!"
        return False, "Şifre silinirken bir hata oluştu!"
        
    def list_services(self):
        return self.encryption.list_entries()
        
    def get_password_info(self, service):
        entry = self.encryption.get_entry(service)
        if entry:
            # Süre bilgisini notlardan al
            expires_in_days = 0
            expiry_date = None
            notes = entry.notes or ""
            
            if "Expires:" in notes:
                try:
                    expiry_str = notes.split("Expires:", 1)[1].split("\n", 1)[0].strip()
                    expiry_date = datetime.strptime(expiry_str, '%Y-%m-%d')
                    expires_in_days = (expiry_date - datetime.now()).days
                except:
                    expires_in_days = 0
            
            return {
                'password': entry.password,
                'created_at': entry.ctime.strftime('%Y-%m-%d %H:%M:%S'),
                'last_updated': entry.mtime.strftime('%Y-%m-%d %H:%M:%S'),
                'expires_at': expiry_date.strftime('%Y-%m-%d %H:%M:%S') if expiry_date else None,
                'is_fixed': expires_in_days == 0
            }
        return None
        
    def toggle_fixed_password(self, service):
        entry = self.encryption.get_entry(service)
        if entry:
            # Mevcut süreyi kontrol et
            info = self.get_password_info(service)
            if info:
                is_fixed = info.get('is_fixed', False)
                # Eğer şifre süresiz ise 90 günlük yap, değilse süresiz yap
                new_expires_in_days = 90 if is_fixed else 0
                if self.encryption.update_entry(service, new_expires_in_days=new_expires_in_days):
                    return True, "Şifre durumu güncellendi!"
        return False, "Şifre durumu güncellenirken bir hata oluştu!"
        
    def check_expiring_passwords(self):
        expiring_passwords = []
        for service in self.list_services():
            info = self.get_password_info(service)
            if info and not info.get('is_fixed', False):
                expiry_date = datetime.strptime(info['expires_at'], '%Y-%m-%d %H:%M:%S')
                days_left = (expiry_date - datetime.now()).days
                if days_left <= 30:  # 30 gün veya daha az kaldıysa
                    expiring_passwords.append({
                        'service': service,
                        'days_left': days_left
                    })
        return expiring_passwords
        
    def update_password(self, service, new_password):
        if not self.master_password:
            return False, "Ana şifre ayarlanmamış!"
            
        entry = self.encryption.get_entry(service)
        if not entry:
            return False, "Bu servis için şifre bulunamadı!"
            
        # Mevcut süre bilgisini al
        info = self.get_password_info(service)
        expires_in_days = 0 if info.get('is_fixed', False) else 90
        
        if self.encryption.update_entry(service, new_password, expires_in_days=expires_in_days):
            return True, "Şifre başarıyla güncellendi!"
        return False, "Şifre güncellenirken bir hata oluştu!"

if __name__ == "__main__":
    from gui import main as gui_main
    gui_main() 
