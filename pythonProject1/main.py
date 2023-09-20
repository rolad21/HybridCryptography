from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import serialization
import os

# Generate RSA Key Pair
def generate_rsa_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_key

private_key, public_key = generate_rsa_key_pair()


# Encrypt Data using AES
def encrypt_aes(data, aes_key):
    salt = os.urandom(16)  # Use the os.urandom function to generate a salt
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    aes_key = kdf.derive(aes_key)

    iv = os.urandom(16)  # Use the os.urandom function to generate an IV
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(data) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    return encrypted_data, iv, salt

data_to_encrypt = input("Enter the secret message: ").encode('utf-8')
aes_key = b'some_random_aes_key'
encrypted_data, iv, salt = encrypt_aes(data_to_encrypt, aes_key)
# Encrypt AES Key using RSA
def encrypt_aes_key_with_rsa(aes_key, recipient_public_key):
    cipher_aes_key = recipient_public_key.encrypt(
        aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher_aes_key

# Assuming you have the recipient's public key as `recipient_public_key`
cipher_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)
private_key_pem, public_key = generate_rsa_key_pair()
private_key = serialization.load_pem_private_key(private_key_pem, password=None)
cipher_aes_key = encrypt_aes_key_with_rsa(aes_key, public_key)

def decrypt_aes_key_with_rsa(cipher_aes_key, private_key):
    aes_key = private_key.decrypt(
        cipher_aes_key,
        rsa_padding.OAEP(
            mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key
decrypted_aes_key = decrypt_aes_key_with_rsa(cipher_aes_key, private_key)
def decrypt_aes(encrypted_data, aes_key, iv):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32
    )
    aes_key = kdf.derive(aes_key)

    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
    decryptor = cipher.decryptor()

    decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

    return decrypted_data

decrypted_data = decrypt_aes(encrypted_data, decrypted_aes_key, iv)
print("Original Message:", data_to_encrypt.decode('utf-8'))
print("Encrypted Data:", encrypted_data.hex())  # Print encrypted data in hexadecimal
print("AES Key:", aes_key.hex())  # Print AES key
print("Decrypted Message:", decrypted_data.decode('utf-8'))