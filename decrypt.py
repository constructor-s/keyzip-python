import keyzip
from argparse import ArgumentParser

if __name__ == '__main__':
    parser = ArgumentParser(description="KeyZip decrypt demo")
    parser.add_argument("--inputfile", type=str)
    parser.add_argument("--privatekeyfile", type=str)
    parser.add_argument("--showpassword", action="store_true")
    args = parser.parse_args()

    with keyzip.KeyTarFile(args.inputfile) as f:
        f.privatekeyfile = args.privatekeyfile
        encrypted_file_name = f.manifest["encrypted_files"][0]

        if args.showpassword:
            print(f.aes_key_b64.decode(keyzip.TEXT_ENCODING))
        with f.decryptfile(encrypted_file_name) as ff:
            ff.list()
