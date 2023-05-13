using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using X509Certificate = Org.BouncyCastle.X509.X509Certificate;

namespace MauiApp1;

public partial class MainPage : ContentPage
{
    int count = 0;

    public MainPage()
    {
        InitializeComponent();
    }

    private void OnCounterClicked(object sender, EventArgs e)
    {
        var cert = CertGenerator.GetCert();
        
        using var x509Store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        x509Store.Open(OpenFlags.ReadWrite);
        
        x509Store.Add(new X509Certificate2(cert.GetEncoded()));
        
        count++;

        if (count == 1)
            CounterBtn.Text = $"Clicked {count} time";
        else
            CounterBtn.Text = $"Clicked {count} times";

        SemanticScreenReader.Announce(CounterBtn.Text);
    }
}

public static class CertGenerator
{
    private static readonly SecureRandom Random = new();

    public static X509Certificate GetCert()
    {
        var keygen = new RsaKeyPairGenerator();
        keygen.Init(new KeyGenerationParameters(Random, 2048));

        var pair = keygen.GenerateKeyPair();

        var cert = GenerateCert(pair);

        return cert;
    }

    private static X509Certificate GenerateCert(AsymmetricCipherKeyPair pair)
    {
        var x509 = new X509V3CertificateGenerator();
        x509.SetSerialNumber(new BigInteger(128, Random));

        var dn = new X509Name("CN=APP_CERTIFICATE CA Certificate");
            
        x509.SetSubjectDN(dn);
        x509.SetIssuerDN(dn);
            
        x509.SetPublicKey(pair.Public);

        x509.SetNotBefore(DateTime.UtcNow);
        x509.SetNotAfter(DateTime.UtcNow.AddYears(15));
            
        var signatureFactory = new Asn1SignatureFactory("SHA256WITHRSA", pair.Private);

        return x509.Generate(signatureFactory);
    }
}