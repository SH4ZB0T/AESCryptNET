using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace Grandstream_Provisioner
{
    class AESCryptNET
    {

        /*
            AES-128
            H1 = MD5(secret + salt)
            H2 = MD5(H1 + secret + salt)

            Key = H1
            IV = H2

            AES-256
            H1 = MD5(secret + salt)
            H2 = MD5(H1 + secret + salt)
            H3 = MD5(H2 + secret + salt)

           Key = H1 + H2
           IV = H3
        */


        private static byte[] GetIteratedMD5(byte[] secretBytes, byte[] saltBytes, int iteration)
        {
            MD5 md5 = MD5.Create();

            byte[] md5Current = new byte[16];
            byte[] secretSalt = new byte[secretBytes.Length + saltBytes.Length];

            Buffer.BlockCopy(secretBytes, 0, secretSalt, 0, secretBytes.Length); // copy secretBytes into secretSalt
            Buffer.BlockCopy(saltBytes, 0, secretSalt, secretBytes.Length, saltBytes.Length); // copy saltBytes in secretSalt

            md5Current = md5.ComputeHash(secretSalt);

            for (int i = 1; i < iteration; i++)
            {
                byte[] md5SecretSalt = new byte[md5Current.Length + secretBytes.Length + saltBytes.Length];

                Buffer.BlockCopy(md5Current, 0, md5SecretSalt, 0, md5Current.Length);
                Buffer.BlockCopy(secretBytes, 0, md5SecretSalt, md5Current.Length, secretBytes.Length);
                Buffer.BlockCopy(saltBytes, 0, md5SecretSalt, md5Current.Length + secretBytes.Length, saltBytes.Length);

                md5Current = md5.ComputeHash(md5SecretSalt);
            }
            md5.Clear();
            return md5Current;
        }

        private static byte[] GetSaltBytes(int numBytes)
        {
            byte[] salt = new byte[numBytes];
            using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
            {
                random.GetBytes(salt);
            }
            return salt;
        }

        public static byte[] DecryptCBC(byte[] cipherTextBodyBytes, string secretString, byte[] saltBytes, int keySize) { return DecryptCBC(cipherTextBodyBytes, Encoding.UTF8.GetBytes(secretString), saltBytes, keySize); }
        public static byte[] DecryptCBC(byte[] cipherTextBodyBytes, byte[] secretBytes, byte[] saltBytes, int keySize)
        {
            byte[] key = null;
            byte[] iv = null;

            if (keySize == 128)
            {
                key = GetIteratedMD5(secretBytes, saltBytes, 1);
                iv = GetIteratedMD5(secretBytes, saltBytes, 2);
            }
            else if (keySize == 256)
            {
                byte[] keyA = GetIteratedMD5(secretBytes, saltBytes, 1);
                byte[] keyB = GetIteratedMD5(secretBytes, saltBytes, 2);
                key = new byte[keyA.Length + keyB.Length];

                Buffer.BlockCopy(keyA, 0, key, 0, keyA.Length); // merge keyA and keyB into key
                Buffer.BlockCopy(keyB, 0, key, keyA.Length, keyB.Length);

                iv = GetIteratedMD5(secretBytes, saltBytes, 3);
            }
            else
                throw new Exception("Key size must be 128 or 256");

            AesManaged aes = new AesManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = keySize;
            aes.BlockSize = 128;
            aes.Key = key;
            aes.IV = iv;

            byte[] clearTextBody = null;

            using (ICryptoTransform Decryptor = aes.CreateDecryptor())
            {
                using (MemoryStream mStream = new MemoryStream())
                {
                    using (CryptoStream CryptoStream = new CryptoStream(mStream, Decryptor, CryptoStreamMode.Write))
                    {
                        CryptoStream.Write(cipherTextBodyBytes, 0, cipherTextBodyBytes.Length);
                        CryptoStream.FlushFinalBlock();

                        clearTextBody = mStream.ToArray();
                        CryptoStream.Close();
                    }
                    mStream.Close();
                }
            }
            aes.Clear();

            return clearTextBody;
        }


        public static byte[] EncryptCBC(byte[] plainTextBytes, string secretString, int keySize) { return EncryptCBC(plainTextBytes, Encoding.UTF8.GetBytes(secretString), keySize); }
        public static byte[] EncryptCBC(byte[] plainTextBytes, byte[] secretBytes, int keySize)
        {
            byte[] saltBytes = GetSaltBytes(8);

            byte[] key = null;
            byte[] iv = null;

            if (keySize == 128)
            {
                key = GetIteratedMD5(secretBytes, saltBytes, 1);
                iv = GetIteratedMD5(secretBytes, saltBytes, 2);
            }
            else if (keySize == 256)
            {
                byte[] keyA = GetIteratedMD5(secretBytes, saltBytes, 1);
                byte[] keyB = GetIteratedMD5(secretBytes, saltBytes, 2);
                key = new byte[keyA.Length + keyB.Length];

                Buffer.BlockCopy(keyA, 0, key, 0, keyA.Length); // merge keyA and keyB into key
                Buffer.BlockCopy(keyB, 0, key, keyA.Length, keyB.Length);

                iv = GetIteratedMD5(secretBytes, saltBytes, 3);
            }
            else
            {
                throw new Exception("Key size must be 128 or 256");
            }

            AesManaged aes = new AesManaged();
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            aes.KeySize = keySize;
            aes.BlockSize = 128;
            aes.Key = key;
            aes.IV = iv;

            byte[] cipherTextBody = null;

            using (ICryptoTransform Encryptor = aes.CreateEncryptor())
            {
                using (MemoryStream mStream = new MemoryStream())
                {
                    using (CryptoStream CryptoStream = new CryptoStream(mStream, Encryptor, CryptoStreamMode.Write))
                    {
                        CryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
                        CryptoStream.FlushFinalBlock();

                        cipherTextBody = mStream.ToArray();
                        CryptoStream.Close();
                    }
                    mStream.Close();
                }
            }

            aes.Clear();

            int cipherTextWithSaltLength = cipherTextBody.Length + 8 + 8; // length + Salted__ + saltBytes
            byte[] salted = Encoding.UTF8.GetBytes("Salted__");
            byte[] cipherTextBytes = new byte[cipherTextWithSaltLength];

            Buffer.BlockCopy(salted, 0, cipherTextBytes, 0, salted.Length);
            Buffer.BlockCopy(saltBytes, 0, cipherTextBytes, 8, saltBytes.Length);
            Buffer.BlockCopy(cipherTextBody, 0, cipherTextBytes, 16, cipherTextBody.Length);

            return cipherTextBytes;
        }
    }
}
