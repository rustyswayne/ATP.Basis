namespace ATP.Basis.Cryptography
{
    /// <summary>
    /// Represents a Cryptography provider.
    /// </summary>
    public interface ICryptographyProvider
    {
        /// <summary>
        /// Encrypts a value.
        /// </summary>
        /// <param name="valueToEncrypt">
        /// The value to encrypt.
        /// </param>
        /// <returns>
        /// The cipher text <see cref="byte[]"/>.
        /// </returns>
        string Encrypt(string valueToEncrypt);

        /// <summary>
        /// Decrypts a cipher.
        /// </summary>
        /// <param name="cipherText">
        /// The cipher text.
        /// </param>
        /// <returns>
        /// The decrypted value.
        /// </returns>
        string Decrypt(string cipherText);
    }
}