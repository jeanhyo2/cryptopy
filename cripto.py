import sys
from PyQt5.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, QTextEdit, QMessageBox, QFileDialog
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Hash import SHA256
import base64
import os

class AesFileApp(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()
    
    def initUI(self):
        self.setWindowTitle('AES File Encryption/Decryption')

        layout = QVBoxLayout()

        self.fileLabel = QLabel('Selected file:')
        layout.addWidget(self.fileLabel)
        
        self.filePath = QLineEdit()
        layout.addWidget(self.filePath)

        self.browseButton = QPushButton('Browse')
        self.browseButton.clicked.connect(self.browse_file)
        layout.addWidget(self.browseButton)

        self.keyLabel = QLabel('Enter key (seed):')
        layout.addWidget(self.keyLabel)
        
        self.keyInput = QLineEdit()
        layout.addWidget(self.keyInput)

        self.encryptButton = QPushButton('Encrypt')
        self.encryptButton.clicked.connect(self.encrypt_file)
        layout.addWidget(self.encryptButton)

        self.decryptButton = QPushButton('Decrypt')
        self.decryptButton.clicked.connect(self.decrypt_file)
        layout.addWidget(self.decryptButton)

        self.resultLabel = QLabel('Result:')
        layout.addWidget(self.resultLabel)
        
        self.resultOutput = QTextEdit()
        self.resultOutput.setReadOnly(True)
        layout.addWidget(self.resultOutput)

        self.setLayout(layout)

    def get_aes_key(self, seed):
        hasher = SHA256.new(seed.encode('utf-8'))
        return hasher.digest()

    def browse_file(self):
        options = QFileDialog.Options()
        fileName, _ = QFileDialog.getOpenFileName(self, "Select File", "", "All Files (*)", options=options)
        if fileName:
            self.filePath.setText(fileName)

    def encrypt_file(self):
        try:
            file_path = self.filePath.text()
            seed = self.keyInput.text()

            if not os.path.exists(file_path):
                QMessageBox.warning(self, 'Error', 'File not found.')
                return

            key = self.get_aes_key(seed)
            cipher = AES.new(key, AES.MODE_CBC)
            iv = cipher.iv

            with open(file_path, 'rb') as file:
                file_data = file.read()

            ct_bytes = cipher.encrypt(pad(file_data, AES.block_size))

            encrypted_file_path = file_path + '.enc'
            with open(encrypted_file_path, 'wb') as file:
                file.write(iv + ct_bytes)

            self.resultOutput.setPlainText(f'File encrypted successfully: {encrypted_file_path}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

    def decrypt_file(self):
        try:
            file_path = self.filePath.text()
            seed = self.keyInput.text()

            if not os.path.exists(file_path):
                QMessageBox.warning(self, 'Error', 'File not found.')
                return

            key = self.get_aes_key(seed)

            with open(file_path, 'rb') as file:
                iv = file.read(16)
                ct = file.read()

            cipher = AES.new(key, AES.MODE_CBC, iv)
            pt = unpad(cipher.decrypt(ct), AES.block_size)

            if file_path.endswith('.enc'):
                decrypted_file_path = file_path[:-4]
            else:
                decrypted_file_path = file_path + '.dec'

            with open(decrypted_file_path, 'wb') as file:
                file.write(pt)

            self.resultOutput.setPlainText(f'File decrypted successfully: {decrypted_file_path}')
        except Exception as e:
            QMessageBox.critical(self, 'Error', str(e))

if __name__ == '__main__':
    app = QApplication(sys.argv)
    aesFileApp = AesFileApp()
    aesFileApp.show()
    sys.exit(app.exec_())
