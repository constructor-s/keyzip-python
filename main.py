import keyzip
from argparse import ArgumentParser

if __name__ == '__main__':
    parser = ArgumentParser(description="KeyZip demo")
    parser.add_argument("--inputfile", type=str)
    parser.add_argument("--privatekeyfile", type=str)
    args = parser.parse_args()

    with keyzip.KeyTarFile(args.inputfile) as f:
        f.privatekeyfile = args.privatekeyfile
        encrypted_file_name = f.manifest["encrypted_files"][0]

        with f.decryptfile(encrypted_file_name) as ff:
            members = ff.getmembers()
            print(members)
