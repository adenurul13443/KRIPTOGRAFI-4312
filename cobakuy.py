import streamlit as st
import collections
import math  # Tambahkan ini untuk mengimpor modul math

def vigenere_encrypt(plain_text, key):
    encrypted_text = ""
    key_length = len(key)
    for i in range(len(plain_text)):
        char = chr((ord(plain_text[i]) + 1) % 256)
        key_char = key[i % key_length]
        encrypted_char = chr((ord(char) + ord(key_char)) % 256)
        encrypted_text += encrypted_char
    return encrypted_text

def vigenere_decrypt(cipher_text, key):
    decrypted_text = ""
    key_length = len(key)
    for i in range(len(cipher_text)):
        char = cipher_text[i]
        key_char = key[i % key_length]
        decrypted_char = chr((ord(char) - ord(key_char) - 1) % 256)
        decrypted_text += decrypted_char
    return decrypted_text

def calculate_ber(original_text, decrypted_text):
    if len(original_text) != len(decrypted_text):
        raise ValueError("Panjang teks asli dan teks terdekripsi harus sama")

    num_errors = sum(1 for a, b in zip(original_text, decrypted_text) if a != b)
    ber = num_errors / len(original_text)
    return ber

def calculate_cer(original_text, decrypted_text):
    if len(original_text) != len(decrypted_text):
        raise ValueError("Panjang teks asli dan teks terdekripsi harus sama")

    num_errors = sum(1 for a, b in zip(original_text, decrypted_text) if a != b)
    cer = num_errors / len(original_text)
    return cer

def calculate_entropy(plain_text):
    text_length = len(plain_text)
    character_counts = collections.Counter(plain_text)  # Menggunakan collections.Counter
    entropy = 0
    for count in character_counts.values():
        probability = count / text_length
        entropy -= probability * math.log(probability, 2)
    return entropy

def calculate_avalanche_effect(original_text, key):
    encrypted_text = vigenere_encrypt(original_text, key)
    total_changes = 0

    for i in range(len(original_text)):
        modified_text = list(original_text)
        for j in range(256):  # Coba semua kemungkinan perubahan
            modified_text[i] = chr(j)
            modified_encrypted_text = vigenere_encrypt(''.join(modified_text), key)

            differences = sum(1 for k in range(len(encrypted_text)) if encrypted_text[k] != modified_encrypted_text[k])
            total_changes += differences

    avalanche_effect = (total_changes / (len(original_text) * 256)) * 100  # Hitung dalam persentase
    return avalanche_effect

# Contoh penggunaan
original_text = st.text_input('Enter the message: ')  # Teks asli
key = st.text_input('Enter the key: ')   # Kunci Vigenere
cipher_text = vigenere_encrypt(original_text, key)  # Enkripsi teks asli
decrypted_text = vigenere_decrypt(cipher_text, key)  # Dekripsi teks terenkripsi

ber = calculate_ber(original_text, decrypted_text)
cer = calculate_cer(original_text, decrypted_text)
avalanche_effect = calculate_avalanche_effect(original_text, key)
entropy = calculate_entropy(cipher_text)

ber_str = str(int(ber * 10000))
cer_str = str(int(cer * 10000))
avalanche_effect_str = str(int(round(avalanche_effect))

if st.button('Enkripsi/Dekripsi', type="primary"):
    st.write(f'Teks Asli: {original_text}')
    st.write(f'Teks Terenkripsi: {cipher_text}')
    st.write(f'Teks Terdekripsi: {decrypted_text}')
    st.write(f'Bit Error Rate (BER): {ber_str}')
    st.write(f'Character Error Rate (CER): {cer_str}')
    st.write(f'Avalanche Effect: {avalanche_effect_str}%')
    st.write(f"Entropy of Encrypted Text: {entropy:.4f} bits per character")
    st.write('Lakukan Enkripsi dan Dekripsi')
else:
    st.write('Lakukan Enkripsi dan Dekripsi')
