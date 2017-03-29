namespace ATP.Basis.Cryptography
{
    using System;
    using System.IO;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// Cryptography helper - uses <see cref="Aes"/>
    /// </summary>
    /// <seealso cref="https://simpledotnetsolutions.wordpress.com/2012/03/22/using-rijndaelmanaged-to-encryptdecrypt/"/>
    internal class AesCryptographyProvider : ICryptographyProvider
    {
        /// <summary>
        /// The salt for the encryption.
        /// </summary>
        private readonly string _seed;

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCryptographyProvider"/> class.
        /// </summary>
        public AesCryptographyProvider()
        {
            this._seed = string.Empty;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AesCryptographyProvider"/> class.
        /// </summary>
        /// <param name="seed">
        /// The salt.
        /// </param>
        internal AesCryptographyProvider(string seed)
        {
            if (seed.IsNullOrWhiteSpace()) throw new ArgumentNullException(nameof(seed));
        }

        /// <inheritdoc />
        public string Encrypt(string valueToEncrypt)
        {
            // Plain Text to be encrypted
            byte[] plainText = Encoding.Unicode.GetBytes(valueToEncrypt);

            // The default key size for RijndaelManaged is 256 bits, while the default blocksize is 128 bits.
            using (var manager = this.GetAes())
            {
                // Now encrypt
                byte[] cipherBytes = null;
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, manager.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(plainText, 0, plainText.Length);
                    }

                    cipherBytes = ms.ToArray();
                }

                return Convert.ToBase64String(cipherBytes);
            }
        }

        /// <inheritdoc />
        public string Decrypt(string encryptedValue)
        {
            var cipherText = Convert.FromBase64String(encryptedValue);

            using (var manager = this.GetAes())
            {
                // ow decrypt
                byte[] plainText2 = null;
                using (var ms = new MemoryStream())
                {
                    using (var cs = new CryptoStream(ms, manager.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherText, 0, cipherText.Length);
                    }

                    plainText2 = ms.ToArray();
                }

                return Encoding.Unicode.GetString(plainText2);
            }
        }

        /// <summary>
        /// Gets the <see cref="Aes"/> manager.
        /// </summary>
        /// <returns>
        /// The <see cref="Aes"/>.
        /// </returns>
        private Aes GetAes()
        {
            var sb = new StringBuilder();
            sb.Append(this._seed);

            // Generate the Salt, with any custom logic and using the above string
            var saltBuilder = new StringBuilder();
            for (var i = 0; i < 8; i++)
            {
                saltBuilder.Append("," + sb.Length);
            }

            byte[] salt = Encoding.ASCII.GetBytes(saltBuilder.ToString());

            // Key generation:- default iterations is 1000 and recomended is 10000
            var pwdGen = new Rfc2898DeriveBytes(sb.ToString(), salt, 10000);

            var manager = Aes.Create();
            

            manager.Key = pwdGen.GetBytes(manager.KeySize / 8);   // This will generate a 256 bits key
            manager.IV = pwdGen.GetBytes(manager.BlockSize / 8);  // This will generate a 256 bits IV

            return manager;
        }
    }
}