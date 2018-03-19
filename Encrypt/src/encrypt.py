__author__ = "Ashraf"

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512, SHA384, SHA256, SHA, MD5
from Crypto import Random
from base64 import b64encode, b64decode
import hashlib


hash = "SHA-512"
BS = 16
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS)

class encryption(object):
    def __init__(self, aeskey, message):
        self.message = message
        self.AES_KEY = aeskey

    @staticmethod
    def message_encrypt(key,msg):

        sender_key_file = open("sender_key.pem", "rb")
        sender_key = sender_key_file.read()
        receiver_key_file = open("receiver_key.pem", "rb")
        receiver_key = receiver_key_file.read()
        sender_key_file.close()
        receiver_key_file.close()
        sender_key = RSA.importKey(sender_key)

        sender_private = sender_key
        receiver_key = RSA.importKey(receiver_key)
        receiver_public = receiver_key.publickey()

        #hash the message to prove its integrity
        bmsg = msg.encode("utf-8")
        m = hashlib.sha512()
        m.update(bmsg)
        hashed = m.digest()

        # Layer-1
        # This is AES encrytpion of the message
        if len(key)<32:
            padding_string = "0000000"
            a = hashlib.md5(padding_string.encode("utf-8")).hexdigest()
            length = len(key)
            len_padding = len(a) - length
            key+=a[:len_padding]
        elif len(key)>32:
            key = key[:32]


        raw = pad(msg)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        message = b64encode(iv + cipher.encrypt(raw))

        #Layer-2
        key = key.encode("utf-8")
        new_key = b"\n\n".join([key,hashed])

        #Signing the key and Hash_of_message
        global hash
        signer = PKCS1_v1_5.new(sender_private)
        digest = SHA512.new()
        digest.update(key)
        signature = b64encode(signer.sign(digest))

        #Layer-3
        # Start RSA encryption using Public key of receiver
        cipher = PKCS1_OAEP.new(receiver_public)
        encrypted = cipher.encrypt(new_key)
        encrypted = b64encode(encrypted)

        #Contents that goes into mail-body
        full_enc = b'\n\n'.join([message,encrypted,signature])
        return full_enc