import keyzip
from pathlib import Path
from argparse import ArgumentParser

if __name__ == '__main__':
    parser = ArgumentParser(description="KeyZip encrypt demo")
    parser.add_argument("--input", type=str, nargs="+")
    parser.add_argument("--output", type=str)
    parser.add_argument("--publickeyfile", type=str)
    args = parser.parse_args()

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)
    with keyzip.KeyTarFile(args.output, "w") as f:
        f.publickeyfile = args.publickeyfile
        f.addencrypt(args.input, archivename="encrypted")
