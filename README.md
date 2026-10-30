# Trisect-Cipher

**Authenticated file encryption with 3-of-3 XOR secret sharing.**

Trisect-Cipher is a lightweight Python command-line tool that encrypts a file using **AES-256-GCM**, then splits the encrypted stream into three independent shares using XOR-based 3-of-3 secret sharing.

All three shares and the separate key file are required to restore the original file.

## Security model

The tool applies two separate protections:

1. **Encryption:** AES-256-GCM provides confidentiality and authentication. Each file chunk is encrypted independently with a fresh 96-bit nonce and authenticated associated data.
2. **Secret sharing:** the encrypted stream is split into three equal-length shares. Two shares reveal no information about the encrypted stream under the assumption that the random shares are generated securely and independently.

For encrypted data `E`, two random strings `A` and `B` are generated:

```text
Share 1 = A
Share 2 = B
Share 3 = E XOR A XOR B

E = Share 1 XOR Share 2 XOR Share 3
```

This is a **3-of-3** scheme: all three shares are necessary. It is not a 2-of-3 threshold scheme.

The key file is a fourth independent recovery component. Keep it separate from all three shares.

## Requirements

- Python 3.10+
- `cryptography`

## Installation

```bash
python -m venv .venv
```

Activate the virtual environment, then install dependencies:

**Windows (Command Prompt):**
```bat
.venv\Scripts\activate
python -m pip install -r requirements.txt
```

**Linux / macOS:**
```bash
source .venv/bin/activate
python -m pip install -r requirements.txt
```

## Usage

### Split and encrypt

```bash
python trisect_cipher.py split path/to/document.pdf backups/document
```

Creates:

```text
backups/document_part1.bin
backups/document_part2.bin
backups/document_part3.bin
backups/document_key.bin
```

You can choose a separate key-file path:

```bash
python trisect_cipher.py split document.pdf backups/document --key-out /secure/location/document.key
```

### Reconstruct and decrypt

```bash
python trisect_cipher.py join \
  backups/document_part1.bin \
  backups/document_part2.bin \
  backups/document_part3.bin \
  /secure/location/document.key \
  restored_document.pdf
```

On Windows Command Prompt, enter the join command on one line.

The program refuses to overwrite existing output files.

## Storage recommendations

- Store each share on a different physical or independently controlled storage location.
- Store the key file separately from all three shares.
- Keep an additional protected backup of the key. A printed QR code is possible, but anyone who obtains a readable copy of the key can decrypt the reconstructed data.
- Test recovery periodically using copies of the shares and key.
- Do not upload all shares and the key to the same account or storage provider.

## Important limitations

- Losing any one share makes recovery impossible with this 3-of-3 design.
- Losing the key file also makes decryption impossible.
- Anyone who obtains all three shares and the key can recover the file.
- AES-GCM authenticates each encrypted chunk, but it does not hide file size.
- This tool is not a substitute for a tested backup strategy. Keep redundant, separately protected backups.
- The tool currently processes data in chunks to limit memory use, but the three output shares are the same size as the encrypted stream, so total storage use is approximately three times the encrypted payload size.
- The key file is stored unencrypted. Its physical and access-control protection is the user's responsibility.



## License

MIT. See [LICENSE](LICENSE).
