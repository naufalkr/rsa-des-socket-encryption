from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

def rsa_encrypt(message, public_key):
    """
    Manual RSA encryption.
    Args:
        message (str): The plaintext message to encrypt.
        public_key (Crypto.PublicKey.RSA.RsaKey): Public key for encryption.

    Returns:
        bytes: Encrypted message.
    """
    n, e = public_key.n, public_key.e
    message_int = bytes_to_long(message.encode('utf-8'))
    encrypted_int = pow(message_int, e, n)
    return long_to_bytes(encrypted_int)

def rsa_decrypt(ciphertext, private_key):
    """
    Manual RSA decryption.
    Args:
        ciphertext (bytes): The encrypted message to decrypt.
        private_key (Crypto.PublicKey.RSA.RsaKey): Private key for decryption.

    Returns:
        str: Decrypted plaintext message.
    """
    n, d = private_key.n, private_key.d
    ciphertext_int = bytes_to_long(ciphertext)
    decrypted_int = pow(ciphertext_int, d, n)
    return long_to_bytes(decrypted_int).decode('utf-8')
