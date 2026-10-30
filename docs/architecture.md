# Architecture

## Data flow

```text
Input file
   |
   v
AES-256-GCM (independent authenticated chunks)
   |
   v
Encrypted stream
   |
   v
3-of-3 XOR secret sharing
   |
   +---- Share 1
   +---- Share 2
   +---- Share 3

AES key -> separate key file
```

## Chunk format

The shared encrypted stream contains:

- 8-byte format marker
- Repeated records:
  - 4-byte big-endian plaintext chunk length
  - 12-byte AES-GCM nonce
  - ciphertext plus 16-byte authentication tag
- 4-byte zero-length end marker

Each chunk's associated authenticated data includes a format-specific prefix, chunk index, and plaintext length. This binds chunks to their position and expected size.

## Recovery

The three shares are XORed back into the encrypted stream. The stream is parsed and each chunk is authenticated and decrypted. The output is first written to a temporary file and moved into place only after all chunks authenticate successfully.
