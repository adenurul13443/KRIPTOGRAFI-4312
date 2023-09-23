from pycipher import Vigenere
import streamlit as st

st.title("Kriptografi")
plain_text=input("Enter the message: ")
key=input("Enter the key: ")
vigenere_cipher = Vigenere (key).encipher(plain_text)
print("---VIGENERE CIPHER---")
print("CIPHER TEXT : ",vigenere_cipher)

from pycipher import Beaufort
beaufort_cipher = Beaufort (key).encipher(plain_text)
d = Beaufort (key).decipher(beaufort_cipher)
print("---BEAUFORT CIPHER---")
print("CIPHER TEXT : ",beaufort_cipher)
print("PLAIN TEXT : ",d)
