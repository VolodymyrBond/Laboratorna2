import os
import base64
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hmac
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding

# Функція для генерації ключа та вектора ініціалізації
def generate_key_iv():
    key = os.urandom(32)  # Генерація 256-бітного ключа 
    iv = os.urandom(16)   # Генерація 128-бітного ключ
    return key, iv

# Функція для шифрування файлу
def encrypt_file(input_file, output_file, key, iv):
    with open(input_file, 'rb') as file:
        data = file.read()

    # Вирівнювання довжини даних до блоку (128 біт)
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    # Шифрування даних за допомогою AES
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Генерація HMAC для забезпечення цілісності
    hmac_instance = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac_instance.update(encrypted_data)
    mac = hmac_instance.finalize()

    # Збереження шифрованих даних та MAC
    with open(output_file, 'wb') as file:
        file.write(iv + mac + encrypted_data)

# Функція для дешифрування файлу
def decrypt_file(input_file, output_file, key):
    with open(input_file, 'rb') as file:
        data = file.read()

    iv = data[:16]  
    mac = data[16:48]  
    encrypted_data = data[48:]  

    # Перевірка MAC
    hmac_instance = hmac.HMAC(key, hashes.SHA256(), backend=default_backend())
    hmac_instance.update(encrypted_data)
    try:
        hmac_instance.verify(mac)
    except Exception as e:
        messagebox.showerror("Error", "MAC verification failed. The data might have been tampered with.")
        return

    # Дешифрування даних
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Вилучення даних
    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    with open(output_file, 'wb') as file:
        file.write(decrypted_data)

# Функція обробки для вибору файлів і виконання процесу
def run_encryption_decryption():
    action = action_var.get()

    if action == "Encrypt":
        input_file = filedialog.askopenfilename(title="Select a file to encrypt")
        if input_file:
            output_file = filedialog.asksaveasfilename(title="Save encrypted file as")
            key, iv = generate_key_iv()
            encrypt_file(input_file, output_file, key, iv)
            messagebox.showinfo("Success", "File encrypted successfully.")

    elif action == "Decrypt":
        input_file = filedialog.askopenfilename(title="Select a file to decrypt")
        if input_file:
            output_file = filedialog.asksaveasfilename(title="Save decrypted file as")
            key = key_entry.get().encode()  # Ключ, введений користувачем
            decrypt_file(input_file, output_file, key)
            messagebox.showinfo("Success", "File decrypted successfully.")

# Головне вікно програми
root = tk.Tk()
root.title("Encryption and Decryption")

# Створення кнопок для програми
action_var = tk.StringVar(value="Encrypt")
encrypt_radio = tk.Radiobutton(root, text="Encrypt", variable=action_var, value="Encrypt")
decrypt_radio = tk.Radiobutton(root, text="Decrypt", variable=action_var, value="Decrypt")
encrypt_radio.pack()
decrypt_radio.pack()

key_label = tk.Label(root, text="Enter decryption key (32 bytes):")
key_label.pack()

key_entry = tk.Entry(root, show="*")
key_entry.pack()

run_button = tk.Button(root, text="Run", command=run_encryption_decryption)
run_button.pack()

# Запуск програми
root.mainloop()
