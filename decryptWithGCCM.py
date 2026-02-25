    
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as sym_padding
import click

@click.command()
@click.argument('file_to_decrpy', type=click.Path(exists=True))
@click.argument('key_file_str', type=click.Path(exists=True))
@click.argument('new_file', type=str)
def decrypt(file_to_decrpy, key_file_str,new_file):
    """decrypt a file to its normal version using GCM for consistency checking"""


    
    with open(key_file_str, "rb") as key_file:
        private_key = serialization.load_pem_private_key(

            key_file.read(),
            password=None,
        )
    
    with open(file_to_decrpy, "rb") as f:
            key_len = int.from_bytes(f.read(2), 'big')
            encrypted_aes_key = f.read(key_len)
            iv = f.read(12)
            len_tag=int.from_bytes(f.read(2), 'big')
            tag =f.read(len_tag)
            encrypted_data = f.read()

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(iv, tag) )
    decryptor = cipher.decryptor()

    data = decryptor.update(encrypted_data) + decryptor.finalize()

    with open(new_file, "wb") as f:
        f.write(data)

    print(f"File '{file_to_decrpy}' decrypted successfully as '{new_file}'.")




if __name__ == '__main__':
    decrypt()