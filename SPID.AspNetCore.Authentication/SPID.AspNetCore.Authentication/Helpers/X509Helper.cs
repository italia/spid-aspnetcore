using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SPID.AspNetCore.Authentication.Helpers
{
    public static class X509Helper
    {
        /// <summary>
        /// Get certificate from file path and password
        /// </summary>
        /// <param name="certFilePath"></param>
        /// <param name="certPassword"></param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateFromFile(string certFilePath, string certPassword)
        {
            if (string.IsNullOrWhiteSpace(certFilePath))
            {
                throw new ArgumentNullException("The certFilePath parameter can't be null or empty.");
            }

            if (string.IsNullOrWhiteSpace(certPassword))
            {
                throw new ArgumentNullException("The certPassword parameter can't be null or empty.");
            }

            if (File.Exists(certFilePath))
            {
                return new X509Certificate2(certFilePath, certPassword,
                        X509KeyStorageFlags.MachineKeySet |
                        X509KeyStorageFlags.PersistKeySet |
                        X509KeyStorageFlags.Exportable);
            }
            else
            {
                throw new FileNotFoundException("Unable to locate certificate");
            }
        }

        /// <summary>
        /// Get certificate from file path and password
        /// </summary>
        /// <param name="certFilePath"></param>
        /// <param name="certPassword"></param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateFromStrings(string certificateString64, string privateKeyXml)
        {
            try
            {
                var rsaCryptoServiceProvider = new RSACryptoServiceProvider();
                rsaCryptoServiceProvider.FromXmlString(privateKeyXml);

                var certificateBytes = Convert.FromBase64String(certificateString64);
                var x509Certificate2 = new X509Certificate2(certificateBytes)
                {
                    PrivateKey = rsaCryptoServiceProvider
                };

                return x509Certificate2;
            }
            catch
            {
                return null;
            }
        }


        /// <summary>
        /// Get certificate from the store
        /// </summary>
        /// <param name="storeLocation"></param>
        /// <param name="storeName"></param>
        /// <param name="findType"></param>
        /// <param name="findValue">Must be a string or a DateTime, depending on findType</param>
        /// <param name="validOnly">Must be false if testing with a self-signed certificate</param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateFromStore(StoreLocation storeLocation, StoreName storeName, X509FindType findType, object findValue, bool validOnly)
        {
            X509Certificate2 certificate = null;

            if (findValue == null)
            {
                throw new ArgumentNullException("The findValue parameter can't be null.");
            }

            X509Store store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection coll = store.Certificates.Find(findType, findValue.ToString(), validOnly);

            if (coll.Count > 0)
            {
                certificate = coll[0];
            }
            store.Close();

            if (certificate != null)
            {
                return certificate;
            }
            else
            {
                throw new FileNotFoundException("Unable to locate certificate");
            }
        }


        public static string CreateSignature(this string payload, X509Certificate2 certificate)
        {
            using var rsa = certificate.GetRSAPrivateKey();
            using var shaHash = SHA256.Create();
            var hash = shaHash.ComputeHash(Encoding.UTF8.GetBytes(payload));
            return Convert.ToBase64String(rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Base64FormattingOptions.None);
        }
    }
}
