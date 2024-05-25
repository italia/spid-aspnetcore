using SPID.AspNetCore.Authentication.Exceptions;
using SPID.AspNetCore.Authentication.Resources;
using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace SPID.AspNetCore.Authentication.Helpers
{
    internal static class X509Helpers
    {
        /// <summary>
        /// Get certificate from file path and password
        /// </summary>
        /// <param name="certFilePath"></param>
        /// <param name="certPassword"></param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateFromFile(string certFilePath, string certPassword)
        {
            BusinessValidation.ValidationNotNullNotWhitespace(certFilePath, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.CertificatePathNullOrEmpty, SpidErrorCode.CertificatePathNullOrEmpty));
            BusinessValidation.ValidationNotNullNotWhitespace(certPassword, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.CertificatePasswordNullOrEmpty, SpidErrorCode.CertificatePasswordNullOrEmpty));

            return new X509Certificate2(certFilePath,
                certPassword,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
        }

        /// <summary>
        /// Get certificate from file path and password
        /// </summary>
        /// <param name="certFilePath"></param>
        /// <param name="certPassword"></param>
        /// <returns></returns>
        public static X509Certificate2 GetCertificateFromStrings(string certificateString64, string certPassword)
        {
            BusinessValidation.ValidationNotNullNotWhitespace(certificateString64, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.CertificateRawStringNullOrEmpty, SpidErrorCode.CertificateRawStringNullOrEmpty));
            BusinessValidation.ValidationNotNullNotWhitespace(certPassword, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.CertificatePasswordNullOrEmpty, SpidErrorCode.CertificatePasswordNullOrEmpty));
            var certificateBytes = Convert.FromBase64String(certificateString64);
            return new X509Certificate2(certificateBytes, certPassword,
                X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
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
            BusinessValidation.ValidationNotNullNotWhitespace(findValue.ToString(), new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.CertificateFindValueNullOrEmpty, SpidErrorCode.CertificateFindValueNullOrEmpty));
            using X509Store store = new X509Store(storeName, storeLocation);
            store.Open(OpenFlags.ReadOnly | OpenFlags.OpenExistingOnly);
            X509Certificate2Collection coll = store.Certificates.Find(findType, findValue.ToString(), validOnly);

            X509Certificate2 certificate = null;
            if (coll.Count > 0)
            {
                certificate = coll[0];
            }

            BusinessValidation.ValidationNotNull(certificate, new SpidException(ErrorLocalization.GenericMessage, ErrorLocalization.CertificateNotFound, SpidErrorCode.CertificateNull));

            return certificate;
        }

        /// <summary>
        /// Creates the signature.
        /// </summary>
        /// <param name="payload">The payload.</param>
        /// <param name="certificate">The certificate.</param>
        /// <returns></returns>
        public static string CreateSignature(this string payload, X509Certificate2 certificate)
        {
            using var rsa = certificate.GetRSAPrivateKey();
            using var shaHash = SHA256.Create();
            var hash = shaHash.ComputeHash(Encoding.UTF8.GetBytes(payload));
            return Convert.ToBase64String(rsa.SignHash(hash, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1), Base64FormattingOptions.None);
        }

        public static byte[] ExportPublicKey(this X509Certificate2 cert)
            => cert.Export(X509ContentType.Cert);
    }
}
