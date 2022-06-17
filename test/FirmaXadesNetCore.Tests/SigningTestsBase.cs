using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace FirmaXadesNetCore.Tests;

public abstract class SigningTestsBase
{
	public static Stream CreateExampleDocumentStream(string elementID = null)
	{
		var xmlDocument = new XmlDocument
		{
			PreserveWhitespace = true,
		};

		xmlDocument.AppendChild(xmlDocument.CreateElement("example-root"));
		XmlElement innerElement = xmlDocument.CreateElement("example-inner");
		innerElement.InnerText = "test text";
		innerElement.SetAttribute("id", elementID ?? "exampleID");
		xmlDocument.DocumentElement.AppendChild(innerElement);

		var stream = new MemoryStream();

		using var writer = XmlWriter.Create(stream, new XmlWriterSettings
		{
			CloseOutput = false,
		});

		xmlDocument.WriteTo(writer);
		writer.Flush();
		writer.Close();

		stream.Seek(0, SeekOrigin.Begin);

		return stream;
	}

	protected static X509Certificate2 CreateSelfSignedCertificate(int keySizeInBits = 4096, string name = "test", string password = "WeNeedASaf3rPassword")
	{
		var distinguishedName = new X500DistinguishedName($"CN={name}");

		using var rsa = RSA.Create(keySizeInBits);

		var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		request.CertificateExtensions.Add(new SubjectAlternativeNameBuilder().Build());

		using X509Certificate2 certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));

		if (OperatingSystem.IsWindows())
		{
			certificate.FriendlyName = name;
		}

		byte[] pfxBytes = certificate.Export(X509ContentType.Pfx, password);

		return new X509Certificate2(pfxBytes, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
	}
}
