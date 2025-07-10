import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                           QHBoxLayout, QPushButton, QLineEdit, QLabel, 
                           QMessageBox, QTableWidget, QTableWidgetItem, QHeaderView,
                           QProgressBar, QDialog, QToolTip, QToolButton, QCheckBox,
                           QSpinBox, QGroupBox, QScrollArea, QInputDialog)
from PyQt5.QtCore import Qt, QTimer, QSize
from PyQt5.QtGui import QFont, QIcon, QPalette, QColor, QClipboard
from main import PasswordManager
from login import LoginDialog
from datetime import datetime

class NotificationLabel(QLabel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QLabel {
                background-color: #4CAF50;
                color: white;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
            }
        """)
        self.setAlignment(Qt.AlignCenter)
        self.hide()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.hide)
        
    
        
    def show_notification(self, message, duration=2000):
        self.setText(message)
        self.show()
        self.timer.start(duration)

class SecurityReportDialog(QDialog):
    def __init__(self, security_data, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🔒 Güvenlik Raporu")
        self.setMinimumSize(600, 400)
        self.init_ui(security_data)
        
    def init_ui(self, security_data):
        layout = QVBoxLayout(self)
        
        # Genel skor
        score_group = QGroupBox("Genel Güvenlik Skoru")
        score_layout = QVBoxLayout()
        
        score_label = QLabel(f"Skor: {security_data['overall_score']:.1f}/100")
        score_label.setStyleSheet("font-size: 24px; font-weight: bold; color: #e94560;")
        score_layout.addWidget(score_label)
        
        score_bar = QProgressBar()
        score_bar.setRange(0, 100)
        score_bar.setValue(int(security_data['overall_score']))
        score_bar.setStyleSheet("""
            QProgressBar {
                height: 20px;
                text-align: center;
            }
            QProgressBar::chunk {
                background-color: #e94560;
            }
        """)
        score_layout.addWidget(score_bar)
        score_group.setLayout(score_layout)
        layout.addWidget(score_group)
        
        # Zayıf şifreler
        if security_data['weak_passwords']:
            weak_group = QGroupBox("⚠️ Zayıf Şifreler")
            weak_layout = QVBoxLayout()
            for weak in security_data['weak_passwords']:
                weak_label = QLabel(f"• {weak['service']}: {weak['strength']['feedback']}")
                weak_label.setStyleSheet("color: #ff6b6b;")
                weak_layout.addWidget(weak_label)
            weak_group.setLayout(weak_layout)
            layout.addWidget(weak_group)
            
        # Sızıntıya uğramış şifreler
        if security_data['breached_passwords']:
            breach_group = QGroupBox("🚨 Sızıntıya Uğramış Şifreler")
            breach_layout = QVBoxLayout()
            for breach in security_data['breached_passwords']:
                breach_label = QLabel(f"• {breach['service']}: {breach['breach_count']} kez sızıntıya uğramış")
                breach_label.setStyleSheet("color: #ff0000;")
                breach_layout.addWidget(breach_label)
            breach_group.setLayout(breach_layout)
            layout.addWidget(breach_group)
            
        # Kapat butonu
        close_button = QPushButton("Kapat")
        close_button.clicked.connect(self.accept)
        layout.addWidget(close_button)

class PasswordGeneratorDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🔑 Şifre Oluşturucu")
        self.setMinimumSize(400, 300)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Uzunluk seçimi
        length_layout = QHBoxLayout()
        length_label = QLabel("Şifre Uzunluğu:")
        self.length_spin = QSpinBox()
        self.length_spin.setRange(8, 64)
        self.length_spin.setValue(16)
        length_layout.addWidget(length_label)
        length_layout.addWidget(self.length_spin)
        layout.addLayout(length_layout)
        
        # Karakter seçenekleri
        self.uppercase_cb = QCheckBox("Büyük Harfler (A-Z)")
        self.uppercase_cb.setChecked(True)
        layout.addWidget(self.uppercase_cb)
        
        self.lowercase_cb = QCheckBox("Küçük Harfler (a-z)")
        self.lowercase_cb.setChecked(True)
        layout.addWidget(self.lowercase_cb)
        
        self.numbers_cb = QCheckBox("Sayılar (0-9)")
        self.numbers_cb.setChecked(True)
        layout.addWidget(self.numbers_cb)
        
        self.special_cb = QCheckBox("Özel Karakterler (!@#$%^&*)")
        self.special_cb.setChecked(True)
        layout.addWidget(self.special_cb)
        
        # Oluşturulan şifre
        self.password_output = QLineEdit()
        self.password_output.setReadOnly(True)
        self.password_output.setStyleSheet("""
            QLineEdit {
                font-family: monospace;
                font-size: 16px;
                padding: 10px;
            }
        """)
        layout.addWidget(self.password_output)
        
        # Butonlar
        button_layout = QHBoxLayout()
        
        generate_button = QPushButton("🔄 Yeni Şifre Oluştur")
        generate_button.clicked.connect(self.generate_password)
        button_layout.addWidget(generate_button)
        
        copy_button = QPushButton("📋 Kopyala")
        copy_button.clicked.connect(self.copy_password)
        button_layout.addWidget(copy_button)
        
        layout.addLayout(button_layout)
        
        # İlk şifreyi oluştur
        self.generate_password()
        
    def generate_password(self):
        parent = self.parent()
        if parent and hasattr(parent, 'pm'):
            password = parent.pm.generate_secure_password(
                length=self.length_spin.value(),
                include_uppercase=self.uppercase_cb.isChecked(),
                include_lowercase=self.lowercase_cb.isChecked(),
                include_numbers=self.numbers_cb.isChecked(),
                include_special=self.special_cb.isChecked()
            )
            self.password_output.setText(password)
            
    def copy_password(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.password_output.text())
        QToolTip.showText(self.mapToGlobal(self.password_output.rect().bottomRight()),
                         "Şifre kopyalandı!", self)

class UpdatePasswordDialog(QDialog):
    def __init__(self, service, current_password, parent=None):
        super().__init__(parent)
        self.service = service
        self.current_password = current_password
        self.setWindowTitle(f"🔑 {service} Şifresini Güncelle")
        self.setMinimumSize(400, 300)
        self.init_ui()
        
    def init_ui(self):
        layout = QVBoxLayout(self)
        
        # Mevcut şifre
        current_layout = QHBoxLayout()
        current_label = QLabel("Mevcut Şifre:")
        self.current_input = QLineEdit()
        self.current_input.setText(self.current_password)
        self.current_input.setReadOnly(True)
        current_layout.addWidget(current_label)
        current_layout.addWidget(self.current_input)
        layout.addLayout(current_layout)
        
        # Yeni şifre
        new_layout = QHBoxLayout()
        new_label = QLabel("Yeni Şifre:")
        self.new_input = QLineEdit()
        self.new_input.setEchoMode(QLineEdit.Password)
        self.new_input.textChanged.connect(self.update_password_strength)
        new_layout.addWidget(new_label)
        new_layout.addWidget(self.new_input)
        layout.addLayout(new_layout)
        
        # Şifre gücü göstergesi
        strength_layout = QHBoxLayout()
        self.strength_label = QLabel('💪 Şifre Gücü:')
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setFixedHeight(15)
        strength_layout.addWidget(self.strength_label)
        strength_layout.addWidget(self.strength_bar)
        layout.addLayout(strength_layout)
        
        # Butonlar
        button_layout = QHBoxLayout()
        
        update_button = QPushButton("🔄 Güncelle")
        update_button.clicked.connect(self.accept)
        button_layout.addWidget(update_button)
        
        cancel_button = QPushButton("❌ İptal")
        cancel_button.clicked.connect(self.reject)
        button_layout.addWidget(cancel_button)
        
        layout.addLayout(button_layout)
        
    def update_password_strength(self):
        password = self.new_input.text()
        strength = 0
        
        if len(password) >= 8:
            strength += 20
        if any(c.isupper() for c in password):
            strength += 20
        if any(c.islower() for c in password):
            strength += 20
        if any(c.isdigit() for c in password):
            strength += 20
        if any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
            strength += 20
            
        self.strength_bar.setValue(strength)
        
        if strength < 40:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #e94560; }")
        elif strength < 80:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #ffd700; }")
        else:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #4CAF50; }")
            
    def get_new_password(self):
        return self.new_input.text()

class PasswordManagerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.pm = PasswordManager()
        self.init_ui()
        
        # Süre kontrolü için timer - 5 dakikada bir kontrol et
        self.timer = QTimer()
        self.timer.timeout.connect(self.check_expiring_passwords)
        self.timer.start(300000)  # 5 dakika
        
    def init_ui(self):
        self.setWindowTitle('🔒 Kryptos')
        self.setGeometry(100, 100, 1200, 700)
        
        # Koyu tema renkleri
        self.setStyleSheet("""
            QMainWindow {
                background-color: #1a1a2e;
            }
            QWidget {
                background-color: #1a1a2e;
                color: #e6e6e6;
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
            QTableWidget {
                background-color: #16213e;
                color: #e6e6e6;
                border: 2px solid #0f3460;
                border-radius: 5px;
                gridline-color: #0f3460;
                font-size: 14px;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QTableWidget::item:selected {
                background-color: #0f3460;
            }
            QHeaderView::section {
                background-color: #16213e;
                color: #e6e6e6;
                padding: 10px;
                border: none;
                font-weight: bold;
                border-bottom: 2px solid #0f3460;
                font-size: 14px;
            }
            QScrollBar:vertical {
                border: none;
                background-color: #16213e;
                width: 12px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #0f3460;
                min-height: 20px;
                border-radius: 6px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #e94560;
            }
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
                height: 0px;
            }
            QMessageBox {
                background-color: #1a1a2e;
            }
            QMessageBox QLabel {
                color: #e6e6e6;
            }
            QMessageBox QPushButton {
                min-width: 80px;
            }
            QProgressBar {
                border: 2px solid #0f3460;
                border-radius: 5px;
                text-align: center;
                background-color: #16213e;
                color: #e6e6e6;
                height: 15px;
            }
            QProgressBar::chunk {
                background-color: #e94560;
                border-radius: 3px;
            }
        """)
        
        # Ana widget ve layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        layout.setSpacing(15)
        layout.setContentsMargins(20, 20, 20, 20)
        
        # Bildirim etiketi
        self.notification = NotificationLabel(self)
        self.notification.setFixedSize(300, 40)
        self.notification.move(
            (self.width() - self.notification.width()) // 2,
            20
        )
        
        # Üst kısım (başlık ve güvenlik skoru)
        top_layout = QHBoxLayout()
        
        # Başlık
        title_label = QLabel('🔒 Kryptos')
        title_label.setStyleSheet("""
            font-size: 28px;
            color: #e94560;
            font-weight: bold;
            padding: 10px;
        """)
        title_label.setAlignment(Qt.AlignLeft)
        
        top_layout.addWidget(title_label)
        
        # Güvenlik skoru butonu
        self.security_button = QPushButton("🔒 Güvenlik Raporu")
        self.security_button.clicked.connect(self.show_security_report)
        top_layout.addWidget(self.security_button)
        
        # Şifre oluşturucu butonu
        self.generator_button = QPushButton("🔑 Şifre Oluşturucu")
        self.generator_button.clicked.connect(self.show_password_generator)
        top_layout.addWidget(self.generator_button)
        
        top_layout.addStretch()
        
        layout.addLayout(top_layout)
        
        # Giriş yap
        login_dialog = LoginDialog()
        if login_dialog.exec_() != QDialog.Accepted:
            sys.exit()
            
        # Ana şifreyi ayarla
        self.pm.set_master_password(login_dialog.password_input.text())
        
        # Servis ve şifre giriş alanları
        input_layout = QHBoxLayout()
        input_layout.setSpacing(10)
        
        self.service_input = QLineEdit()
        self.service_input.setPlaceholderText('Servis Adı')
        self.service_input.setMinimumWidth(200)
        
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Şifre')
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setMinimumWidth(200)
        self.password_input.textChanged.connect(self.update_password_strength)
        
        input_layout.addWidget(QLabel('🌐 Servis'))
        input_layout.addWidget(self.service_input)
        input_layout.addWidget(QLabel('🔑 Şifre'))
        input_layout.addWidget(self.password_input)
        
        # Şifre gücü göstergesi
        strength_layout = QHBoxLayout()
        self.strength_label = QLabel('💪 Şifre Gücü:')
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 100)
        self.strength_bar.setValue(0)
        self.strength_bar.setFixedHeight(15)
        strength_layout.addWidget(self.strength_label)
        strength_layout.addWidget(self.strength_bar)
        
        # Butonlar
        button_layout = QHBoxLayout()
        button_layout.setSpacing(10)
        
        self.add_button = QPushButton('➕ Şifre Ekle')
        self.add_button.clicked.connect(self.add_password)
        
        button_layout.addWidget(self.add_button)
        
        # Tablo
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels([
            '🌐 Servis',
            '🔑 Şifre',
            '📅 Oluşturma Tarihi',
            '🔄 Son Güncelleme',
            '⏳ Bitiş Tarihi',
            '⚙️ İşlemler'
        ])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Fixed)
        self.table.setColumnWidth(5, 240)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setAlternatingRowColors(True)
        self.table.cellDoubleClicked.connect(self.handle_cell_double_click)
        self.table.setStyleSheet("""
            QTableWidget {
                alternate-background-color: #0f3460;
            }
            QTableWidget::item {
                padding: 8px;
            }
            QHeaderView::section {
                padding: 8px;
                font-size: 12px;
            }
        """)
        
        # Layout'a widget'ları ekle
        layout.addLayout(input_layout)
        layout.addLayout(strength_layout)
        layout.addLayout(button_layout)
        layout.addWidget(self.table)
        
        # Tabloyu güncelle
        self.update_table()
        
    def update_table(self):
        self.table.setRowCount(0)
        services = self.pm.list_services()
        
        for service in services:
            info = self.pm.get_password_info(service)
            if not info:
                continue
                
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setRowHeight(row, 50)
            
            # Servis adı
            self.table.setItem(row, 0, QTableWidgetItem(f"🌐 {service}"))
            
            # Şifre (gizli)
            success, password = self.pm.get_password(service)
            if success:
                password_item = QTableWidgetItem('*' * len(password))
                password_item.setData(Qt.UserRole, password)
                self.table.setItem(row, 1, password_item)
            else:
                password_item = QTableWidgetItem('*' * len(info['password']))
                self.table.setItem(row, 1, password_item)
            
            # Oluşturma tarihi
            created_at = datetime.strptime(info['created_at'], '%Y-%m-%d %H:%M:%S')
            self.table.setItem(row, 2, QTableWidgetItem(f"📅 {created_at.strftime('%d.%m.%Y %H:%M')}"))
            
            # Son güncelleme
            last_updated = datetime.strptime(info['last_updated'], '%Y-%m-%d %H:%M:%S')
            self.table.setItem(row, 3, QTableWidgetItem(f"🔄 {last_updated.strftime('%d.%m.%Y %H:%M')}"))
            
            # Bitiş tarihi
            if info.get('is_fixed', False):
                expires_item = QTableWidgetItem(f"⏳ Süresiz")
                expires_item.setForeground(QColor('#4CAF50'))  # Yeşil
            else:
                expires_at = datetime.strptime(info['expires_at'], '%Y-%m-%d %H:%M:%S')
                days_left = (expires_at - datetime.now()).days
                expires_item = QTableWidgetItem(f"⏳ {expires_at.strftime('%d.%m.%Y')} ({days_left} gün)")
                if days_left <= 7:
                    expires_item.setForeground(QColor('#e94560'))  # Kırmızı
                elif days_left <= 30:
                    expires_item.setForeground(QColor('#ffd700'))  # Sarı
            self.table.setItem(row, 4, expires_item)
            
            # İşlem butonları için widget
            button_widget = QWidget()
            button_layout = QHBoxLayout(button_widget)
            button_layout.setContentsMargins(5, 5, 5, 5)
            button_layout.setSpacing(10)
            
            # Göster/Gizle butonu
            show_button = QPushButton()
            show_button.setText('Göster')
            show_button.setToolTip('Şifreyi Göster/Gizle')
            show_button.setFixedSize(70, 30)
            show_button.setStyleSheet("""
                QPushButton {
                    background-color: #16213e;
                    color: #e6e6e6;
                    border: 2px solid #0f3460;
                    border-radius: 5px;
                    font-size: 11px;
                    font-weight: bold;
                    padding: 5px;
                }
                QPushButton:hover {
                    background-color: #0f3460;
                    border: 2px solid #e94560;
                }
                QPushButton:pressed {
                    background-color: #e94560;
                }
            """)
            show_button.clicked.connect(lambda checked, r=row: self.toggle_password_visibility_in_table(r))
            
            # Güncelle butonu
            update_button = QPushButton()
            update_button.setText('Güncelle')
            update_button.setToolTip('Şifreyi Güncelle')
            update_button.setFixedSize(70, 30)
            update_button.setStyleSheet("""
                QPushButton {
                    background-color: #16213e;
                    color: #4CAF50;
                    border: 2px solid #4CAF50;
                    border-radius: 5px;
                    font-size: 11px;
                    font-weight: bold;
                    padding: 5px;
                }
                QPushButton:hover {
                    background-color: #4CAF50;
                    color: #e6e6e6;
                }
                QPushButton:pressed {
                    background-color: #388E3C;
                }
            """)
            update_button.clicked.connect(lambda checked, s=service: self.update_password(s))
            
            # Sabit/Tut butonu
            fixed_button = QPushButton()
            is_fixed = info.get('is_fixed', False)
            fixed_button.setText('🔒 Sabit' if is_fixed else '🔓 Tut')
            fixed_button.setToolTip('Şifreyi Sabit Tut' if not is_fixed else 'Sabit Şifreyi Kaldır')
            fixed_button.setFixedSize(70, 30)
            fixed_button.setStyleSheet("""
                QPushButton {
                    background-color: #16213e;
                    color: #4CAF50;
                    border: 2px solid #4CAF50;
                    border-radius: 5px;
                    font-size: 11px;
                    font-weight: bold;
                    padding: 5px;
                }
                QPushButton:hover {
                    background-color: #4CAF50;
                    color: #e6e6e6;
                }
                QPushButton:pressed {
                    background-color: #388E3C;
                }
            """)
            fixed_button.clicked.connect(lambda checked, s=service: self.toggle_fixed_password(s))
            
            # Sil butonu
            delete_button = QPushButton()
            delete_button.setText('Sil')
            delete_button.setToolTip('Şifreyi Sil')
            delete_button.setFixedSize(70, 30)
            delete_button.setStyleSheet("""
                QPushButton {
                    background-color: #16213e;
                    color: #e94560;
                    border: 2px solid #e94560;
                    border-radius: 5px;
                    font-size: 11px;
                    font-weight: bold;
                    padding: 5px;
                }
                QPushButton:hover {
                    background-color: #e94560;
                    color: #e6e6e6;
                }
                QPushButton:pressed {
                    background-color: #c1121f;
                }
            """)
            delete_button.clicked.connect(lambda checked, s=service: self.delete_password_from_table(s))
            
            button_layout.addWidget(show_button)
            button_layout.addWidget(update_button)
            button_layout.addWidget(fixed_button)
            button_layout.addWidget(delete_button)
            button_layout.setAlignment(Qt.AlignCenter)
            
            self.table.setCellWidget(row, 5, button_widget)
            
    def add_password(self):
        service = self.service_input.text()
        password = self.password_input.text()
        
        if not service or not password:
            QMessageBox.warning(self, 'Kryptos', '❌ Lütfen servis adı ve şifre girin!')
            return
            
        success, message = self.pm.add_password(service, password)
        if success:
            self.service_input.clear()
            self.password_input.clear()
            self.update_table()
            self.notification.show_notification('✅ ' + message)
        else:
            QMessageBox.warning(self, 'Kryptos', '❌ ' + message)

    def update_password_strength(self):
        password = self.password_input.text()
        strength = 0
        
        if len(password) >= 8:
            strength += 20
        if any(c.isupper() for c in password):
            strength += 20
        if any(c.islower() for c in password):
            strength += 20
        if any(c.isdigit() for c in password):
            strength += 20
        if any(c in '!@#$%^&*(),.?":{}|<>' for c in password):
            strength += 20
            
        self.strength_bar.setValue(strength)
        
        if strength < 40:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #e94560; }")
        elif strength < 80:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #ffd700; }")
        else:
            self.strength_bar.setStyleSheet("QProgressBar::chunk { background-color: #4CAF50; }")

    def toggle_fixed_password(self, service):
        success, message = self.pm.toggle_fixed_password(service)
        if success:
            self.update_table()
            self.notification.show_notification('✅ ' + message)
        else:
            QMessageBox.warning(self, 'Kryptos', '❌ ' + message)

    def check_expiring_passwords(self):
        expiring_passwords = self.pm.check_expiring_passwords()
        if expiring_passwords:
            for pwd in expiring_passwords:
                service = pwd['service']
                days_left = pwd['days_left']
                
                if days_left <= 0:
                    # Şifre süresi dolmuş
                    reply = QMessageBox.question(
                        self, 
                        'Kryptos',
                        f'⚠️ {service} servisinin şifresinin süresi doldu!',
                        QMessageBox.Yes | QMessageBox.No | QMessageBox.Cancel,
                        QMessageBox.Yes
                    )
                    
                    if reply == QMessageBox.Yes:
                        # Şifreyi güncelle
                        self.service_input.setText(service)
                        self.password_input.setFocus()
                        self.notification.show_notification(f"📝 {service} şifresini güncelleyin")
                    elif reply == QMessageBox.No:
                        # Şifreyi sil
                        self.delete_password_from_table(service)
                else:
                    # Şifre süresi yakında dolacak
                    self.notification.show_notification(f'⚠️ {service} servisinin şifresinin süresi {days_left} gün içinde dolacak!')

    def handle_cell_double_click(self, row, column):
        if column == 1:  # Şifre sütunu
            password_item = self.table.item(row, 1)
            if password_item:
                password = password_item.data(Qt.UserRole)
                if password:
                    clipboard = QApplication.clipboard()
                    clipboard.setText(password)
                    
                    # Kopyalandı bildirimi
                    service = self.table.item(row, 0).text().replace('🌐 ', '')
                    self.notification.show_notification(f'✅ {service} şifresi kopyalandı!')

    def toggle_password_visibility_in_table(self, row):
        password_item = self.table.item(row, 1)
        show_button = self.table.cellWidget(row, 5).findChild(QPushButton)
        
        if password_item.text().startswith('*'):
            # Şifreyi göster
            password = password_item.data(Qt.UserRole)
            password_item.setText(password)
            show_button.setText('Gizle')
        else:
            # Şifreyi gizle
            password = password_item.text()
            password_item.setText('*' * len(password))
            show_button.setText('Göster')

    def delete_password_from_table(self, service):
        reply = QMessageBox.question(
            self,
            'Kryptos',
            f'⚠️ {service} servisinin şifresini silmek istediğinizden emin misiniz?',
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No
        )
        
        if reply == QMessageBox.Yes:
            success, message = self.pm.delete_password(service)
            if success:
                self.update_table()
                self.notification.show_notification('✅ ' + message)
            else:
                QMessageBox.warning(self, 'Kryptos', '❌ ' + message)

    def show_security_report(self):
        security_data = self.pm.calculate_overall_security_score()
        dialog = SecurityReportDialog(security_data, self)
        dialog.exec_()
        
    def show_password_generator(self):
        dialog = PasswordGeneratorDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            generated_password = dialog.password_output.text()
            if generated_password:
                self.password_input.setText(generated_password)
                self.update_password_strength()

    def update_password(self, service):
        """Şifre güncelleme işlemini başlatır"""
        # Mevcut şifreyi al
        success, current_password = self.pm.get_password(service)
        if not success:
            QMessageBox.warning(self, 'Kryptos', '❌ Şifre alınamadı!')
            return
            
        # Güncelleme penceresini göster
        dialog = UpdatePasswordDialog(service, current_password, self)
        if dialog.exec_() == QDialog.Accepted:
            new_password = dialog.get_new_password()
            
            if not new_password:
                QMessageBox.warning(self, 'Kryptos', '❌ Lütfen yeni şifre girin!')
                return
                
            # Şifreyi güncelle
            success, message = self.pm.update_password(service, new_password)
            if success:
                self.update_table()
                self.notification.show_notification('✅ ' + message)
            else:
                QMessageBox.warning(self, 'Kryptos', '❌ ' + message)

def main():
    app = QApplication(sys.argv)
    window = PasswordManagerGUI()
    window.show()
    sys.exit(app.exec_()) 
