using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Azure.WebJobs;
using Microsoft.Azure.WebJobs.Extensions.Http;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace GetCertificate
{
    public static class GetCertificate
    {
        private static string PemTextBuilder(string prefix, string suffix, byte[] contents) 
        {
            StringBuilder builder = new StringBuilder();

            builder.Append(prefix);
            builder.Append("\n");

            string base64 = Convert.ToBase64String(contents);

            int offset = 0;
            const int LineLength = 64;

            while (offset < base64.Length)
            {
                int lineEnd = Math.Min(offset + LineLength, base64.Length);
                builder.Append(base64.Substring(offset, lineEnd - offset));
                builder.Append("\n");
                offset = lineEnd;
            }

            builder.Append(suffix);
            return builder.ToString();
        }

        public static string GetCSR(CertificateRequest request)
        {
            byte[] pkcs10 = request.CreateSigningRequest();

            return PemTextBuilder("-----BEGIN CERTIFICATE REQUEST-----","-----END CERTIFICATE REQUEST-----", pkcs10);
        }

        public static string GetPrivateKey(RSA rsa)
        {
            byte[] pkcs10 = rsa.ExportRSAPrivateKey();
            return PemTextBuilder("-----BEGIN RSA PRIVATE KEY-----","-----END RSA PRIVATE KEY-----", pkcs10);
        }

        [FunctionName("certdata")]
        public static async Task<IActionResult> Run(
            [HttpTrigger(AuthorizationLevel.Anonymous, "get", Route = null)] HttpRequest req,
            ILogger log)
        {
            RSA rsa = RSA.Create();
            rsa.KeySize = 2048;

            CertificateRequest certReq = new CertificateRequest(
            "CN=AWS IoT Certificate, O=Amazon",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

            var privKey = GetPrivateKey(rsa);
            var csr = GetCSR(certReq);

                return new OkObjectResult(new {
                    privKey = privKey,
                    csr = csr
                });
        }
    }
}
