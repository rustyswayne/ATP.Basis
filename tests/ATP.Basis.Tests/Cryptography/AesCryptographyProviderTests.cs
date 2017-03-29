using System;

namespace ATP.Basis.Tests.Cryptography
{
    using ATP.Basis.Cryptography;

    using Microsoft.VisualStudio.TestTools.UnitTesting;

    [TestClass]
    public class AesCryptographyProviderTests
    {
        private ICryptographyProvider provider = new AesCryptographyProvider("test.seed.not.to.share");

        [TestMethod]
        public void CanEncryptAndDecryptValue()
        {
            const string value = "test-value";

            var encrypted = provider.Encrypt(value);

            Console.WriteLine($"{value} becomes: {encrypted}");

            var decrypted = provider.Decrypt(encrypted);

            Assert.AreEqual<string>(value, decrypted);

        }
    }
}
