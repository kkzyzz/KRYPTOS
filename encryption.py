from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
import os
from datetime import datetime, timedelta
import pytz

class Encryption:
    def __init__(self, database_path='passwords.kdbx'):
        self.database_path = database_path
        self.kp = None
        self.timezone = pytz.UTC
        
    def _get_expiry_time(self, days):
        """Süre bitiş zamanını hesaplar"""
        if days <= 0:
            return None
        now = datetime.now(self.timezone)
        return now + timedelta(days=days)
        
    def create_database(self, master_password):
        """Yeni bir KDBX veritabanı oluşturur"""
        if not os.path.exists(self.database_path):
            self.kp = PyKeePass(self.database_path, password=master_password)
            self.kp.save()
            return True
        return False
        
    def open_database(self, master_password):
        """Mevcut KDBX veritabanını açar"""
        try:
            self.kp = PyKeePass(self.database_path, password=master_password)
            return True
        except CredentialsError:
            return False
            
    def add_entry(self, title, password, notes='', expires_in_days=90):
        """Veritabanına yeni bir giriş ekler"""
        if self.kp:
            # Süre bilgisini notlara ekle
            if expires_in_days > 0:
                expiry_date = (datetime.now() + timedelta(days=expires_in_days)).strftime('%Y-%m-%d')
                notes = f"Expires: {expiry_date}\n{notes}"
            
            self.kp.add_entry(
                destination_group=self.kp.root_group,
                title=title,
                username='',
                password=password,
                url='',
                notes=notes
            )
            self.kp.save()
            return True
        return False
        
    def get_entry(self, title):
        """Belirli bir başlığa sahip girişi getirir"""
        if self.kp:
            entries = self.kp.find_entries(title=title)
            if entries:
                return entries[0]
        return None
        
    def delete_entry(self, title):
        """Belirli bir başlığa sahip girişi siler"""
        if self.kp:
            entry = self.get_entry(title)
            if entry:
                self.kp.delete_entry(entry)
                self.kp.save()
                return True
        return False
        
    def list_entries(self):
        """Tüm girişlerin başlıklarını listeler"""
        if self.kp:
            return [entry.title for entry in self.kp.entries]
        return []
        
    def update_entry(self, title, new_password=None, new_notes=None, expires_in_days=None):
        """Mevcut bir girişi günceller"""
        if self.kp:
            entry = self.get_entry(title)
            if entry:
                if new_password:
                    entry.password = new_password
                    
                # Notları güncelle
                notes = entry.notes or ""
                if "Expires:" in notes:
                    notes = notes.split("Expires:", 1)[1].split("\n", 1)[1] if "\n" in notes.split("Expires:", 1)[1] else ""
                
                if expires_in_days is not None:
                    if expires_in_days > 0:
                        expiry_date = (datetime.now() + timedelta(days=expires_in_days)).strftime('%Y-%m-%d')
                        notes = f"Expires: {expiry_date}\n{notes}"
                
                if new_notes is not None:
                    notes = new_notes
                    
                entry.notes = notes
                self.kp.save()
                return True
        return False 
