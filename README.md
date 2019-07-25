# FCrypt
Program to encrypt and decrypt files (C#)

# Abstract

|||
|:---:|---|
|Cipher algorithum|AES|
|Key size|256 bit|
|Block size|128 bit|
|Crypto mode|CBC|

## Encrypted file format (`.fcrypt`)

```
+--------------------------------+-------------------------------------------------------+
|    Initial vector (16 byte)    |    Encryped data (compressed by Deflate algorithm)    |
+--------------------------------+-------------------------------------------------------+
```
