from keyzip import TEXT_ENCODING
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
from argparse import ArgumentParser
from base64 import b64decode
import sys

ERROR_SENTINEL = "ERROR"

if __name__ == '__main__':
    args = sys.argv[1:]

    parser = ArgumentParser(description="RSA decrypt demo")
    parser.add_argument("--showdecryptedtext", action="store_true")
    parser.add_argument("--privatekeyfile", type=str)
    parser.add_argument("--encryptedb64", type=str)
    args = parser.parse_args(args=args)

    if args.showdecryptedtext:
        with open(args.privatekeyfile) as f:
            private_pem_text = "".join(f.readlines())
            private_key = RSA.importKey(private_pem_text)

        cipher_rsa = PKCS1_v1_5.new(private_key)
        encrypted_bytes = b64decode(args.encryptedb64)
        decrypted_bytes = cipher_rsa.decrypt(encrypted_bytes, sentinel=ERROR_SENTINEL)
        decrypted_text = decrypted_bytes.decode(encoding=TEXT_ENCODING)

        print(decrypted_text)
