from unittest import TestCase
import keyzip
import os
import pathlib


class Test_EncryptDecrypt(TestCase):
    def test_encrypt_decrypt(self):
        pathlib.Path("output").mkdir(exist_ok=True)
        with open("output/private.pem", "wb") as pri, open("output/public.pem", "wb") as pub:
            keyzip.save_rsa_key_pair(pri, pub)
        self.assertTrue(os.path.exists("output/private.pem"))
        self.assertTrue(os.path.exists("output/public.pem"))

        with keyzip.KeyTarFile("output/temp.tar", "w") as f:
            f.publickeyfile = "output/public.pem"
            f.addencrypt(["keyzip"], archivename="encrypted")
        self.assertTrue(os.path.exists("output/temp.tar"))

        with keyzip.KeyTarFile("output/temp.tar") as f:
            f.privatekeyfile = "output/private.pem"
            encrypted_file_name = f.manifest["encrypted_files"][0]
            with f.decryptfile(encrypted_file_name) as ff:
                with ff.extractfile("keyzip/__init__.py") as pyf:
                    saved = pyf.read()
        with open("keyzip/__init__.py", "rb") as f:
            original = f.read()
        self.assertEqual(saved, original)
