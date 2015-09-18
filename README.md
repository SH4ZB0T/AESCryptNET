# AESCryptNET
A C# .NET library for facilitating OpenSS-compatible enryption and decryption
Headers are as defined below:
```c#
    public static byte[] EncryptCBC(byte[] plainTextBytes, string secretString, int keySize)
    public static byte[] EncryptCBC(byte[] plainTextBytes, byte[] secretBytes, int keySize)
    public static byte[] DecryptCBC(byte[] cipherTextBodyBytes, string secretString, byte[] saltBytes, int keySize)
    public static byte[] DecryptCBC(byte[] cipherTextBodyBytes, byte[] secretBytes, byte[] saltBytes, int keySize)
```
## OpenSSL compatibility
The created outputs are compatible with the output of the following OpenSSL features:
* aes-128-cbc
* aes-256-cbc
Example equivalent OpenSSL equivalent commands:
```
    openssl enc -e -aes-256-cbc -p -k secret_password -in file.plain -in file.encrypted
    openssl enc -d -aes-256-cbc -p -k secret_password -in file.encrypted -out file.plain
```