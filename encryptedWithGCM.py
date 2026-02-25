    
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import click
import os
import hashlib


#https://pycryptodome.readthedocs.io/en/latest/src/cipher/modern.html#gcm-mode nota ue diz arui o iv deve ser de 12bytes nao sei p  
#https://stackoverflow.com/questions/64505267/java-aes-gcm-nopadding-encryption-does-not-increment-the-counter-of-the-iv-after?noredirect=1&lq=1
# https://crypto.stackexchange.com/questions/42412/gcm-padding-or-not doesnt nedd pading string aprouch
BUF_SIZE = 65536

@click.command()
@click.argument('file_to_encryp', type=click.Path(exists=True))
@click.argument('key_file_str', type=click.Path(exists=True))
@click.argument('new_file', type=str)
def encrypted(file_to_encryp, key_file_str,new_file):
    """Encrypted function takes a normal file and encrypt"""


    
    with open(key_file_str, "rb") as key_file:
        public_key = serialization.load_pem_public_key(

            key_file.read(),
        )
    aes_key = os.urandom(32)  
    iv = os.urandom(12)
    data=bytearray()
    with open(file_to_encryp, "rb") as f:
        while True:
            new_data = f.read(BUF_SIZE)
            if not new_data:
                break
            data.extend(new_data)


    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    tag = encryptor.tag


    encrypted_aes_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(new_file, "wb") as f:
        f.write(len(encrypted_aes_key).to_bytes(2, 'big'))
        f.write(encrypted_aes_key)
        f.write(iv)
        f.write(len(tag).to_bytes(2, 'big'))
        f.write(tag)
        f.write(encrypted_data)

    print(f"File '{file_to_encryp}' encrypted successfully as '{new_file}'.")






if __name__ == '__main__':
    encrypted()