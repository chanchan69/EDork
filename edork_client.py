from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_PKCS1_v1_5
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from os import urandom

RSA_PUBLIC_KEY = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsJXpzc4fUzuD9wsCjOIX
erl+pH7ZTDJEh3cNxF9bMSetH8738LuYoJXd2TuxcZ/0/fE7JwxOCfayEUbjTwX7
eLqRmRLTKlXaHb19DFeXhYjEtB1MT5URJnQFs6iWA59+0AsR/LPdmEdM4CM358UX
l2jptEgS3ClkYyZSo1SQNEkwtQ10jmwrVuWrff6hl4taok43d/bMdr/qUrYLNDZn
bN4uaFw0PSJBJKZy79laGZrq96iBbqDzrOvuEfLzpML+15ctomTMqD7yMOkknANV
13DRIhCUcaRRiRN9TE4hEpTKNGc08BEKxR21hagHUD153mBNgKB1XQhzwJtrx00n
ZwIDAQAB
-----END PUBLIC KEY-----"""  # this public key is shared (duh, its public). the private component of this key is required to decrypt the .edork output


def encrypt_payload(data: bytes) -> bytes:
    aes_key = urandom(16)
    aes_cipher = AES.new(aes_key, AES.MODE_CBC)

    cipher_text = aes_cipher.encrypt(pad(data, AES.block_size))
    iv = aes_cipher.iv

    rsa_key = RSA.importKey(RSA_PUBLIC_KEY.encode())
    rsa_cipher = Cipher_PKCS1_v1_5.new(rsa_key)
    enc_key = rsa_cipher.encrypt(aes_key)

    return enc_key + iv + cipher_text


fp = input("dork file to encrypt: ").replace('"', "")
op = fp.replace(".txt", ".edork")
data = open(fp, "rb").read()

final_data = encrypt_payload(data)

open(op, "wb+").write(final_data)

print(f"wrote your edorks to {op}")
