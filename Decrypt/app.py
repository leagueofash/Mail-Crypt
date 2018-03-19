__author__ = "Ashraf"

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512
from base64 import b64decode
import re, os
import hashlib
BLOCK_SIZE = 16
unpad = lambda s: s[:-ord(s[len(s) - 1:])]

class Decryption:

    @staticmethod
    def decypt_mail():
        file = open("IncomingMail.txt", "rb")
        mail_content = file.read()
        print(mail_content)
        mail_content = mail_content.decode("utf-8")
        processing_data = mail_content.split("\n")
        print(processing_data)

        #extracting sender's public key and Receiver's private key
        sender_key_file = open("sender_key.pem", "rb")
        sender_key = sender_key_file.read()
        receiver_key_file = open("receiver_key.pem", "rb")
        receiver_key = receiver_key_file.read()
        sender_key_file.close()
        receiver_key_file.close()
        sender_key = RSA.importKey(sender_key)
        sender_public = sender_key.publickey()
        receiver_pri_key = RSA.importKey(receiver_key)

        #print("{}\n{}\n{}".format(receiver_key,receiver_key.exportKey("PEM"),sender_public))

        #extracting and changing the contents that we want for decrpting
        enc_message = processing_data[2]
        enc_message = enc_message.rstrip("\r").encode("utf-8")
        raw_key = processing_data[4]
        print(raw_key)
        raw_key = raw_key.rstrip("\r")
        #raw_key = raw_key.encode("utf-8")
        signature = processing_data[6]
        signature = signature.rstrip("\r").encode("utf-8")
        print("{}\n{}\n{}\n".format(enc_message,raw_key,signature))

        #extracting the key from the mail! Done by using private key of receiver(RSA decryption)
        cipher = PKCS1_OAEP.new(receiver_pri_key)
        decode_key = b64decode(raw_key)
        key = cipher.decrypt(decode_key)
        print(key)
        #decry = cipher.decrypt(ast.literal_eval(str(raw_key)))
        print("{}\n".format(key))
        xyz = key.split(b"\n\n")
        key = xyz[0]
        hash = xyz[1]
        #seperate the key and hash
        padding_string = "0000000"
        a = hashlib.md5(padding_string.encode("utf-8")).hexdigest()
        #print(a)
        key = key.decode("utf-8")
        longest = ""
        i = 0
        for x in key:
            if re.search(x, a):
                s = x
                while re.search(s, a):
                    if len(s) > len(longest):
                        longest = s
                    if i + len(s) == len(key):
                        break
                    s = key[i:i + len(s) + 1]
            i += 1
        print(longest)
        index = key.find(longest)
        #actual_key = key[:index]
        print("\n\n\n{}".format(key))

        #verify the key
        signature = b64decode(signature)
        print(signature)
        signer = PKCS1_v1_5.new(sender_public)
        digest = SHA512.new()
        digest.update(key.encode("utf-8"))
        print(signer.verify(digest,signature))

        #decrypt the message
        message = b64decode(enc_message)
        iv = message[0:BLOCK_SIZE]
        something = AES.new(key, AES.MODE_CBC, iv)
        actual_message= unpad(something.decrypt(message[16:]))

        #check for intergrity of message
        Hash_of_msg = actual_message
        m = hashlib.sha512()
        m.update(Hash_of_msg)
        hashed = m.digest()
        print(hashed)

        if hashed == hash:
            integrity_check = "Message Integrity Proven"
        else:
            integrity_check ="No Intact and Changed"

        display_file_hndlr = open("DisplayMail.txt","wb")
        sender_email = processing_data[0].encode("utf-8")
        display_file_hndlr.write(sender_email)
        display_file_hndlr.write(b"\n")
        subject = processing_data[1].encode("utf-8")
        display_file_hndlr.write(subject)
        display_file_hndlr.write(b"\n")
        plaintext_msg = actual_message
        display_file_hndlr.write(plaintext_msg)
        display_file_hndlr.write(b"\n")
        display_file_hndlr.write(integrity_check.encode("utf-8"))

xyz = Decryption()
xyz.decypt_mail()
os.system('xdg-open "DisplayMail.txt"')