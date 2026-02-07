import os
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidTag
import mnemonic
import base64

class PDFEncoder:
    def __init__(self):
        self.mnemonic = mnemonic.Mnemonic("english")
    def generate_mnemonic(self, strength=256):
        return self.mnemonic.generate(strength=strength)
    def mnemonic_to_key(self,mnemonic_words,salt=None):
        seed = self.mnemonic.to_seed(mnemonic_words, passphrase="")
        # HKDF 提取前32字节作为 AES 密钥
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'pdf-encryption-v1',
            backend=default_backend()
        )
        return hkdf.derive(seed)
    def encrypt_pdf(self, input_path, mnemonic_words):
        with open(input_path, 'rb') as f:
            plaintext = f.read()
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self.mnemonic_to_key(mnemonic_words, salt)
        aesgcm = AESGCM(key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
        encrypted_data = salt + nonce + ciphertext
        encoded_data = base64.b85encode(encrypted_data)
        return encoded_data
    def decrypt_pdf(self, encoded_data, mnemonic_words):
        encrypted_data = base64.b85decode(encoded_data)
        salt = encrypted_data[:16]
        nounce = encrypted_data[16:28]
        ciphertext = encrypted_data[28:]
        key = self.mnemonic_to_key(mnemonic_words, salt)
        aesgcm = AESGCM(key)
        plaintext = aesgcm.decrypt(nounce, ciphertext, None)
        return plaintext

def fix_samename(path):
    base, ext = os.path.splitext(path)
    counter = 1
    new_path = path
    while os.path.exists(new_path):
        new_path = f"{base}({counter}){ext}"
        counter += 1
    return new_path

def main():
    input_action = input('encode/decode?(e/d)')
    if input_action=='e':
        if input("Do you have a mnemonic words? (y/n)")=='y':
            mnemonic_words = input("Enter your mnemonic words: ")
        else:
            mnemonic_words = PDFEncoder().generate_mnemonic()
        print('Your mnemonic words:',mnemonic_words)
        input_path = input("Enter the path of the PDF file to encrypt: ")
        if input_path[0]=="'" and input_path[-1]=="'":
            input_path = input_path[1:-1]
        encoder = PDFEncoder()
        encoded_data = encoder.encrypt_pdf(input_path, mnemonic_words)
        output_path = Path(input_path).parent/(Path(input_path).stem + '_encrypted.cryp')
        output_path = fix_samename(str(output_path))
        with open(output_path, 'wb') as f:
            f.write(encoded_data)
        print('the encrypted file has been saved as:',output_path)
    elif input_action=='d':
        mnemonic_words = input("Enter your mnemonic words: ")
        input_path = input("Enter the path of the encrypted file to decrypt: ")
        if input_path[0]=="'" and input_path[-1]=="'":
            input_path = input_path[1:-1]
        encoder = PDFEncoder()
        with open(input_path, 'rb') as f:
            encoded_data = f.read()
        try:
            plaintext = encoder.decrypt_pdf(encoded_data, mnemonic_words)
        except InvalidTag:
            print("ERROR:uncorrect mnemonic words or corrupted file")
            return
        output_path = Path(input_path).parent/(Path(input_path).stem + '_decrypted.pdf')
        output_path = fix_samename(str(output_path))
        with open(output_path, 'wb') as f:
            f.write(plaintext)
        print('the decrypted PDF file has been saved as:',output_path)
if __name__ == "__main__":
    main()