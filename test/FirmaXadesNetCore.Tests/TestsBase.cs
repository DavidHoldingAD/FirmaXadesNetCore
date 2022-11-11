using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace FirmaXadesNetCore.Tests;

public abstract class TestsBase
{
	public static MemoryStream CreateExampleDocumentStream(string elementID = null)
	{
		var xmlDocument = new XmlDocument
		{
			PreserveWhitespace = true,
		};

		xmlDocument.AppendChild(xmlDocument.CreateElement("example-root"));
		XmlElement innerElement = xmlDocument.CreateElement("example-inner");
		innerElement.InnerText = "test text";
		innerElement.SetAttribute("id", elementID ?? "exampleID");
		innerElement.SetAttribute("xmlns:test", "http://www.test.org/");
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

	public static Stream CreateExampleDocumentSignedStream(string elementID,
		SignaturePackaging signaturePackaging = SignaturePackaging.Enveloped,
		string digestMethodUri = null,
		string signatureMethodUri = null)
	{
		if (elementID is null)
		{
			throw new ArgumentNullException(nameof(elementID));
		}

		using Stream stream = CreateExampleDocumentStream(elementID);

		using X509Certificate2 certificate = CreateSelfSignedCertificate();

		// Sign
		var service = new XadesService();
		var parameters = new LocalSignatureParameters(certificate)
		{
			SignaturePackaging = signaturePackaging,
			DataFormat = signaturePackaging != SignaturePackaging.Enveloped
				&& signaturePackaging != SignaturePackaging.Enveloping
					? new DataFormat { MimeType = "text/xml" }
					: null,
			ElementIdToSign = signaturePackaging == SignaturePackaging.InternallyDetached
				? elementID
				: null,
			DigestMethod = digestMethodUri is not null
				? DigestMethod.GetByUri(digestMethodUri)
				: DigestMethod.SHA512,
			SignatureMethod = signatureMethodUri is not null
				? SignatureMethod.GetByUri(signatureMethodUri)
				: SignatureMethod.RSAwithSHA512,
			SignatureCommitments = new[]
			{
				new SignatureCommitment(SignatureCommitmentType.ProofOfCreation),
			},
		};

		SignatureDocument document = service.Sign(stream, parameters);

		AssertValid(document);

		var result = new MemoryStream();

		document.Save(result);

		result.Seek(0, SeekOrigin.Begin);

		return result;
	}

	protected static void AssertValid(SignatureDocument signatureDocument,
		XadesValidationFlags validationFlags = XadesValidationFlags.AllChecks,
		bool validateTimestamps = true)
	{
		Assert.IsNotNull(signatureDocument);

		// Serialize to stream
		using var stream = new MemoryStream();
		signatureDocument.Save(stream);
		stream.Seek(0, SeekOrigin.Begin);

		// Validate
		var service = new XadesService();
		ValidationResult result = service.Validate(signatureDocument, validationFlags, validateTimestamps);

		// Assert
		Assert.IsNotNull(result);
		Assert.IsTrue(result.IsValid, $"{result.Message}:{result.Exception}");
	}

	protected static X509Certificate2 CreateSelfSignedCertificate(int keySizeInBits = 2048, string name = "test", string password = "WeNeedASaf3rPassword")
	{
		var distinguishedName = new X500DistinguishedName($"CN={name}");

		using var rsa = RSA.Create(keySizeInBits);

		var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
		request.CertificateExtensions.Add(new SubjectAlternativeNameBuilder().Build());

		using X509Certificate2 certificate = request.CreateSelfSigned(new DateTimeOffset(DateTime.UtcNow.AddDays(-1)), new DateTimeOffset(DateTime.UtcNow.AddDays(3650)));

#if NET6_0_OR_GREATER
		if (OperatingSystem.IsWindows())
		{
			certificate.FriendlyName = name;
		}
#endif

		byte[] pfxBytes = certificate.Export(X509ContentType.Pfx, password);

		return new X509Certificate2(pfxBytes, password, X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
	}
}
