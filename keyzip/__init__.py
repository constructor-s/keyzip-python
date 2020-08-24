import pyzipper
from pyzipper import AESZipFile
from Cryptodome.PublicKey import RSA
from Cryptodome.Cipher import PKCS1_v1_5
from Cryptodome.Random import get_random_bytes
from tarfile import TarFile
from base64 import b64decode, b64encode
import json
import tempfile
import time

TEXT_ENCODING = "UTF-8"
AES_BLOCK_SIZE = 16


class KeyTarFile(TarFile):
    ERROR_SENTINEL = "ERROR"
    MANIFEST_FILE = "manifest.json"
    WRITE_VERSION = "2.0"
    LIB_NAME = "python"
    cipher_class = PKCS1_v1_5
    cipher_name = "RSA/ECB/PKCS1PADDING"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if self.mode == "r":
            with self.extractfile(self.MANIFEST_FILE) as mf:
                self.manifest = json.load(mf)
        elif self.mode == "w":  # manifest.json does not exist yet
            self.manifest = {
                "version": self.WRITE_VERSION,
                "lib": self.LIB_NAME,
                "encrypted_files": [],
            }
            self._aes_key_b64 = b64encode(get_random_bytes(AES_BLOCK_SIZE))
        else:
            raise NotImplementedError("Unsupported operation mode %r" % self.mode)

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

    def addencrypt(self, names, arcnames=None, archivename=None):
        if arcnames is None:
            arcnames = names
        if archivename is None:
            archivename = names[0]

        # Create temporary "archivename.tar.zip"
        with tempfile.SpooledTemporaryFile() as zfobj:
            with AESZipFile(zfobj, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES) as zf:
                zf.setpassword(self._aes_key_b64)

                # Create temporary "archivename.tar"
                with tempfile.SpooledTemporaryFile() as tfobj:
                    with TarFile(fileobj=tfobj, mode="w") as tf:

                        # Add files to "archivename.tar"
                        for (n, an) in zip(names, arcnames):
                            tf.add(n, arcname=an, recursive=True)

                        # Now "archivename.tar" is completely written,
                        # seek to beginning of file and write to "archivename.tar.zip"
                        tfobj.seek(0)
                        zf.writestr(archivename + ".tar", tfobj.read())

            # Now "archivename.tar.zip" is completely written,
            # find out how large this file is by the current position using tell(),
            # then seek to beginning of file and addfile to the root tar
            ti = TarFile.tarinfo(archivename + ".tar.zip")
            ti.size = zfobj.tell()
            ti.mtime = round(time.time())
            zfobj.seek(0)
            self.addfile(ti, zfobj)
            self.manifest["encrypted_files"].append(ti.name)

    def close(self):
        if not self.closed and self.mode == "w":
            with tempfile.SpooledTemporaryFile() as f:
                manifest_json = json.dumps(self.manifest)
                f.write(manifest_json.encode(TEXT_ENCODING))

                ti = TarFile.tarinfo(self.MANIFEST_FILE)
                ti.size = f.tell()
                ti.mtime = round(time.time())
                f.seek(0)
                self.addfile(ti, f)

        super(KeyTarFile, self).close()

    @property
    def privatekeyfile(self):
        return self._private_pem

    @privatekeyfile.setter
    def privatekeyfile(self, file):
        self._private_pem = file

        with open(file) as f:
            private_pem_text = f.read()

        private_key = RSA.importKey(private_pem_text)
        self.cipher = self.cipher_class.new(private_key)

    @property
    def publickeyfile(self):
        return self._public_pem

    @publickeyfile.setter
    def publickeyfile(self, file):
        self._public_pem = file

        with open(file) as f:
            public_pem_text = "".join(f.readlines())

        public_key = RSA.importKey(public_pem_text)
        self.cipher = self.cipher_class.new(public_key)
        self.manifest["public_key"] = public_pem_text
        self.manifest["cipher"] = self.cipher_name
        self.manifest["encrypted_key"] = b64encode(self.cipher.encrypt(self._aes_key_b64)).decode(TEXT_ENCODING)

def save_rsa_key_pair(private_file, public_file, bits=2048):
    """
    Reference: https://pycryptodome.readthedocs.io/en/latest/src/examples.html
    """

    key = RSA.generate(bits)
    private_key = key.export_key()
    private_file.write(private_key)

    public_key = key.publickey().export_key()
    public_file.write(public_key)
