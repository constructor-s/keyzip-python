# keyzip-python
A minimal, cross-language, 7z-GUI-compatible wrapper scheme (.tar.zip.tar) to achieve asymmetric RSA encryption, filename encryption, and ZIP compression using PEM format public and private keys

## What this is
A protocol to package file or files into a `.tar.zip.tar` format. Features:
- Secure
  - Encrypt/decrypt file(s) using AES zip
  - Encrypt filenames as well (by packaging into the innermost `.tar`)
  - Encrypt the AES key with RSA
- Simple and compatible
  - Easy cross-programming-language compatibility by using most common cryptographic features
  - For compatibility, uses `RSA/ECB/PKCS1PADDING` in Java or `PKCS1_v1_5` in Python
  - Read in key files in PEM format
- Compression
  - Compress file(s) using the most compatible algorithm (i.e. DEFLATE)
- Human GUI friendly
  - Compatible with commonly-installed GUI archive viewers (i.e. 7z) to browse data easily by a human (given the AES key)
- Extensible
  - Metadata stored in `manifest.json` that allows other private metadata fields

## Why
I need to collect data through an Android (Java) app distributed to users, package the data securely, and then analyze it using Python or process it server-side with Node.js or just browse through it manually using 7z.

### Why not PGP Zip
There just doesn't seem to be consistent and simple desktop or programming language support for the format, especially if the archive needs to be shared with an average computer user or corporate computer, plus I assume no good package browser GUI like 7z exists.

## What this is not
While I believe the approach is sound and all cryptographic operations are handled by popular libraries, I am not liable for any security issues (please raise them in [issues](/../../issues)). There are also potentially more efficient compression methods, but DEFLATE is used for compatibilty.
