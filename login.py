from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QLineEdit, QPushButton, QMessageBox
from PyQt5.QtCore import Qt
from pykeepass import PyKeePass, create_database
import os

class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self.init_ui()
        
    def init_ui(self):
        self.setWindowTitle('🔒 Giriş')
        self.setFixedSize(400, 200)
        self.setStyleSheet("""
            QDialog {
                background-color: #1a1a2e;
            }
            QLabel {
                color: #e6e6e6;
                font-size: 14px;
                font-weight: bold;
            }
            QLineEdit {
                background-color: #16213e;
                color: #e6e6e6;
                border: 2px solid #0f3460;
                padding: 10px;
                border-radius: 5px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 2px solid #e94560;
            }
            QPushButton {
                background-color: #16213e;
                color: #e6e6e6;
                border: 2px solid #0f3460;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #0f3460;
                border: 2px solid #e94560;
            }
            QPushButton:pressed {
                background-color: #e94560;
            }
        """)
        
        layout = QVBoxLayout()
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        self.password_label = QLabel('🔑 Ana Şifre:')
        layout.addWidget(self.password_label)
        
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.returnPressed.connect(self.verify_password)
        layout.addWidget(self.password_input)
        
        self.login_button = QPushButton('🔐 Giriş Yap')
        self.login_button.clicked.connect(self.verify_password)
        layout.addWidget(self.login_button)
        
        self.setLayout(layout)
        
        if not os.path.exists('passwords.kdbx'):
            self.create_master_password()
            return
    
    def create_master_password(self):
        self.setWindowTitle('🔒 Ana Şifre Oluştur')
        self.password_label.setText('🔑 Yeni Ana Şifre:')
        self.login_button.setText('💾 Kaydet')
        self.login_button.clicked.disconnect()
        self.login_button.clicked.connect(self.save_master_password)
    
    def save_master_password(self):
        password = self.password_input.text()
        
        if not password:
            QMessageBox.warning(self, 'Hata', '❌ Lütfen bir ana şifre girin!')
            return
            
        if len(password) < 8:
            QMessageBox.warning(self, 'Hata', '❌ Ana şifre en az 8 karakter olmalıdır!')
            return
        
        try:
            if os.path.exists('passwords.kdbx'):
                os.remove('passwords.kdbx')
            create_database('passwords.kdbx', password=password)
            QMessageBox.information(self, 'Başarılı', '✅ Ana şifre başarıyla oluşturuldu!')
            self.accept()
        except Exception as e:
            QMessageBox.warning(self, 'Hata', f'❌ Veritabanı oluşturma hatası: {str(e)}')
    
    def verify_password(self):
        try:
            password = self.password_input.text()
            if not password:
                QMessageBox.warning(self, 'Hata', '❌ Lütfen ana şifreyi girin!')
                return
                
            if not os.path.exists('passwords.kdbx'):
                self.create_master_password()
                return
                
            kp = PyKeePass('passwords.kdbx', password=password)
            self.accept()
        except Exception as e:
            QMessageBox.warning(self, 'Hata', f'❌ Hatalı şifre! Hata: {str(e)}')
            self.password_input.clear() 