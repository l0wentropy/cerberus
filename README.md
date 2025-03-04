# cerberus

### AES256-GCM encryption tool

Keys management: RSA, Elliptic Curves (ECIES), Argon2

Built against: OpenSSL, Argon2 shared libs

```
Encryption: 
        cerberus --encrypt --in file.in --out file.out --ec-public pub.pem --argon2=d
        cerberus --encrypt --in file.in --out file.out --pwd --key-file file.key --iterations=18
        cerberus --encrypt --in file.in --out file.out --rsa-public pub.pem --tag file.tag

Decryption: 
        cerberus --decrypt --in file.in --out file.out --ec-private priv.pem
        cerberus --decrypt --in file.in --out file.out --pwd --tag file.tag
        cerberus --decrypt --in file.in --out file.out --rsa-private priv.pem --key-file rsa_pem.pwd


Argon2 options:
        --argon2 i/d/id (id default)
        --iterations 1 to 2^32−1 (16 default)
        --threads 1 to 2^24−1 (degree of parallelism, 4 default)
        --memory 1 to 32 (memory usage of 2^N KiB, default 20)

        Argon2 options are omitted with decryption process as those will be taken from encrypted file metadata
        In case any reason to force using other than stored values add --force flag

Attach/detach AES-GCM verification tag:
        --tag file.tag

        Add --force flag in order to skip tag verification

```
