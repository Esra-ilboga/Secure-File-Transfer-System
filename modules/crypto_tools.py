from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
import pickle

def generate_rsa_keypair(private_path, public_path):
    key = RSA.generate(2048)
    with open(private_path, 'wb') as f:
        f.write(key.export_key())
    with open(public_path, 'wb') as f:
        f.write(key.publickey().export_key())

def load_private_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

def load_public_key(path):
    with open(path, 'rb') as f:
        return RSA.import_key(f.read())

def aes_encrypt(data, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return cipher.nonce, ciphertext, tag

def aes_decrypt(nonce, ciphertext, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)

def rsa_encrypt(key, public_key):
    cipher_rsa = PKCS1_OAEP.new(public_key)
    return cipher_rsa.encrypt(key)

def rsa_decrypt(encrypted_key, private_key):
    cipher_rsa = PKCS1_OAEP.new(private_key)
    return cipher_rsa.decrypt(encrypted_key)

def decrypt_packet(combined_data, private_key):
    packet = pickle.loads(combined_data)
    aes_key = rsa_decrypt(packet['aes_key'], private_key)
    return aes_decrypt(packet['nonce'], packet['data'], packet['tag'], aes_key)