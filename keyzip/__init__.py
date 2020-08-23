from pyzipper import AESZipFile
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
from tarfile import TarFile
from base64 import b64decode
import json

TEXT_ENCODING = "UTF-8"


class KeyTarFile(TarFile):
    ERROR_SENTINEL = "ERROR"
    MANIFEST_FILE = "manifest.json"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        manifest_tarinfo = self.getmember(self.MANIFEST_FILE)
        with self.extractfile(manifest_tarinfo) as mf:
            self.manifest = json.load(mf)

        self.cipher_class = PKCS1_v1_5
        self.cipher = None

    def decryptfile(self, member):
        """
        Decrypt the encrypted_key using the cipher
        (therefore must have already created the cipher, e.g. by setting self.keyfile),
        then use TarFile.extractfile to extract the .tar.zip file and return the extracted inner .tar file as TarFile
        """
        encrypted_key_b64 = self.manifest["encrypted_key"]
        encrypted_key_bytes = b64decode(encrypted_key_b64)
        decrypted_key = self.cipher.decrypt(encrypted_key_bytes, sentinel=self.ERROR_SENTINEL)

        # TODO: are dangling handles a problem?
        f = self.extractfile(member)
        f = AESZipFile(f)
        f.setpassword(decrypted_key)
        f = TarFile(fileobj=f.open(f.namelist()[0]))

        return f

    @property
    def privatekeyfile(self):
        return self._private_pem

    @privatekeyfile.setter
    def privatekeyfile(self, file):
        self._private_pem = file

        with open(file) as f:
            private_pem_text = "".join(f.readlines())

        private_key = RSA.importKey(private_pem_text)
        self.cipher = self.cipher_class.new(private_key)
