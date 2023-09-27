using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

const string usage = "Usage: CheckCertificate.exe <URI>\nE.g.\nCheckCertificate https://www.github.com";
if (args.Length != 1 || string.IsNullOrWhiteSpace(args[0]))
{
    Console.WriteLine(usage);
    return 1;
}

if (!Uri.TryCreate(args[0], UriKind.Absolute, out var uri))
{
    Console.WriteLine($"Not a valid URI: {args[0]}\n{usage}");
    return 1;
}

var httpClientHandler = new HttpClientHandler
{
    ServerCertificateCustomValidationCallback = WriteCertificateChain
};

using var client = new HttpClient(httpClientHandler);
using var response = await client.SendAsync(
    new HttpRequestMessage(HttpMethod.Head, uri));

return 0;

bool WriteCertificateChain(HttpRequestMessage httpRequestMessage, X509Certificate2? x509Certificate2,
    X509Chain? x509Chain, SslPolicyErrors sslPolicyErrors)
{
    Console.WriteLine($"Requested URI: {httpRequestMessage.RequestUri}");
    Console.WriteLine("====================================\n");

    if (x509Chain?.ChainElements == null)
        Console.WriteLine("No certificates in the chain. How is this possible?");
    else
    {
        for (var chainIndex = 0; chainIndex < x509Chain.ChainElements.Count; chainIndex++)
        {
            var chainElement = x509Chain.ChainElements[chainIndex];
            var chainCert = chainElement.Certificate;
            Console.WriteLine($"Certificate {chainIndex} from chain:\n");
            Console.WriteLine($"Subject:\t{chainCert.Subject}");
            Console.WriteLine($"Issuer:\t\t{chainCert.Issuer}");
            Console.WriteLine($"Effective date:\t{chainCert.GetEffectiveDateString()}");
            Console.WriteLine($"Expiry date:\t{chainCert.GetExpirationDateString()}");
            Console.WriteLine($"Version:\t{chainCert.Version}");
            Console.WriteLine($"Thumbprint:\t{chainCert.Thumbprint}");
            foreach (var chainElementStatus in chainElement.ChainElementStatus)
                Console.WriteLine($"Chain element status:\t{chainElementStatus.StatusInformation}");
            Console.WriteLine("====================================\n");
        }
        
        Console.WriteLine($"SSL Errors: {sslPolicyErrors}");
    }

    // Always returning true so an exception isn't thrown
    return true;
}