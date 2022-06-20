using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using FirmaXadesNetCore.Clients;

namespace FirmaXadesNetCore.Tests;

[TestClass]
public class SigningTests : SigningTestsBase
{
	private const string FreeTSAUrl = "https://freetsa.org/tsr";

	[TestMethod]
	// RSA-SHA1
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA512Url)]
	// RSA-SHA256
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA512Url)]
	// RSA-SHA384
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA512Url)]
	// RSA-SHA512
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA512Url)]
	public void Sign_Method_Validate(string signatureMethod, string digestMethod)
	{
		var service = new XadesService();

		using Stream stream = CreateExampleDocumentStream(elementID: "test");
		using X509Certificate2 certificate = CreateSelfSignedCertificate();

		// Sign
		SignatureDocument document = service.Sign(stream, new LocalSignatureParameters
		{
			SignaturePackaging = SignaturePackaging.Enveloped,
			Signer = new Signer(certificate),
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = "test",
			DigestMethod = DigestMethod.GetByUri(digestMethod),
			SignatureMethod = SignatureMethod.GetByUri(signatureMethod),
		});

		AssertValid(document);
	}

	[TestMethod]
	// RSA-SHA1
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA512Url)]
	// RSA-SHA256
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA512Url)]
	// RSA-SHA384
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA512Url)]
	// RSA-SHA512
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA512Url)]
	public void Sign_Counter_Validate(string signatureMethod, string digestMethod)
	{
		var service = new XadesService();

		using Stream stream = CreateExampleDocumentStream(elementID: "test");
		using X509Certificate2 certificate = CreateSelfSignedCertificate();

		// Sign
		SignatureDocument signatureDocument = service.Sign(stream, new LocalSignatureParameters
		{
			SignaturePackaging = SignaturePackaging.Enveloped,
			Signer = new Signer(certificate),
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = "test",
			DigestMethod = DigestMethod.GetByUri(digestMethod),
			SignatureMethod = SignatureMethod.GetByUri(signatureMethod),
		});

		// Counter sign
		signatureDocument = service.CounterSign(signatureDocument, new LocalSignatureParameters
		{
			SignaturePackaging = SignaturePackaging.Enveloped,
			Signer = new Signer(certificate),
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = "test",
			DigestMethod = DigestMethod.GetByUri(digestMethod),
			SignatureMethod = SignatureMethod.GetByUri(signatureMethod),
		});

		AssertValid(signatureDocument);
	}

	[TestMethod]
	// RSA-SHA1
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA1Url, SignedXml.XmlDsigSHA512Url)]
	// RSA-SHA256
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA256Url, SignedXml.XmlDsigSHA512Url)]
	// RSA-SHA384
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA384Url, SignedXml.XmlDsigSHA512Url)]
	// RSA-SHA512
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigRSASHA512Url, SignedXml.XmlDsigSHA512Url)]
	public void Sign_Co_Validate(string signatureMethod, string digestMethod)
	{
		var service = new XadesService();

		using Stream stream = CreateExampleDocumentStream(elementID: "test");
		using X509Certificate2 certificate = CreateSelfSignedCertificate();

		// Sign
		SignatureDocument signatureDocument = service.Sign(stream, new LocalSignatureParameters
		{
			SignaturePackaging = SignaturePackaging.InternallyDetached,
			Signer = new Signer(certificate),
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = "test",
			DigestMethod = DigestMethod.GetByUri(digestMethod),
			SignatureMethod = SignatureMethod.GetByUri(signatureMethod),
		});

		// Counter sign
		signatureDocument = service.CoSign(signatureDocument, new LocalSignatureParameters
		{
			SignaturePackaging = SignaturePackaging.InternallyDetached,
			Signer = new Signer(certificate),
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = "test",
			DigestMethod = DigestMethod.GetByUri(digestMethod),
			SignatureMethod = SignatureMethod.GetByUri(signatureMethod),
		});

		AssertValid(signatureDocument);
	}

	[TestMethod]
	[DoNotParallelize]
	[DataRow(SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigSHA512Url)]
	public void Sign_UpgradeXAdES_T_Validate(string digestMethod)
	{
		var service = new XadesService();
		var upgraderService = new XadesUpgraderService();

		using Stream stream = CreateExampleDocumentStream(elementID: "test");
		using X509Certificate2 certificate = CreateSelfSignedCertificate();

		// Sign
		SignatureDocument signatureDocument = service.Sign(stream, new LocalSignatureParameters
		{
			SignaturePackaging = SignaturePackaging.Enveloped,
			Signer = new Signer(certificate),
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = "test",
			DigestMethod = DigestMethod.GetByUri(digestMethod),
			SignatureMethod = SignatureMethod.RSAwithSHA256,
		});

		// Add timestamp
		using var timestampClient = new TimeStampClient(new Uri(FreeTSAUrl));
		upgraderService.Upgrade(signatureDocument, SignatureFormat.XadesT, new Upgraders.Parameters.UpgradeParameters
		{
			TimeStampClient = timestampClient,
			DigestMethod = DigestMethod.GetByUri(digestMethod),
		});

		AssertValid(signatureDocument);
	}

	[TestMethod]
	[DoNotParallelize]
	[DataRow(SignedXml.XmlDsigSHA1Url)]
	[DataRow(SignedXml.XmlDsigSHA256Url)]
	[DataRow(SignedXml.XmlDsigSHA384Url)]
	[DataRow(SignedXml.XmlDsigSHA512Url)]
	[DataRow(SignedXml.XmlDsigSHA512Url)]
	public void Sign_UpgradeXAdES_XL_Validate(string digestMethod)
	{
		var service = new XadesService();
		var upgraderService = new XadesUpgraderService();

		using Stream stream = CreateExampleDocumentStream(elementID: "test");
		using X509Certificate2 certificate = CreateSelfSignedCertificate();

		// Sign
		SignatureDocument signatureDocument = service.Sign(stream, new LocalSignatureParameters
		{
			SignaturePackaging = SignaturePackaging.Enveloped,
			Signer = new Signer(certificate),
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = "test",
			DigestMethod = DigestMethod.GetByUri(digestMethod),
			SignatureMethod = SignatureMethod.RSAwithSHA256,
		});

		// Add timestamp
		using var timestampClient = new TimeStampClient(new Uri(FreeTSAUrl));
		upgraderService.Upgrade(signatureDocument, SignatureFormat.XadesXL, new Upgraders.Parameters.UpgradeParameters
		{
			TimeStampClient = timestampClient,
			DigestMethod = DigestMethod.GetByUri(digestMethod),
		});

		AssertValid(signatureDocument);
	}

	[TestMethod]
	[DataRow(SignaturePackaging.Enveloped)]
	[DataRow(SignaturePackaging.Enveloping)]
	[DataRow(SignaturePackaging.InternallyDetached)]
	public void Sign_Packaging_Validate(SignaturePackaging packaging)
	{
		var service = new XadesService();

		using Stream stream = CreateExampleDocumentStream(elementID: "test");
		using X509Certificate2 certificate = CreateSelfSignedCertificate();

		// Sign
		SignatureDocument signatureDocument = service.Sign(stream, new LocalSignatureParameters
		{
			SignaturePackaging = packaging,
			Signer = new Signer(certificate),
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = packaging == SignaturePackaging.InternallyDetached
				? "test"
				: null,
		});

		AssertValid(signatureDocument);
	}

	[TestMethod]
	[DataRow(SignaturePackaging.Enveloped)]
	[DataRow(SignaturePackaging.Enveloping)]
	[DataRow(SignaturePackaging.InternallyDetached)]
	public void Sign_Remote_Validate(SignaturePackaging packaging)
	{
		var service = new XadesService();

		using Stream stream = CreateExampleDocumentStream(elementID: "test");

		var xmlDocument = new XmlDocument
		{
			PreserveWhitespace = true,
		};
		xmlDocument.Load(stream);

		using X509Certificate2 certificate = CreateSelfSignedCertificate();
		using var publicCertificate = new X509Certificate2(certificate.Export(X509ContentType.Cert));

		// Get digest
		SignatureDocument signatureDocument = service.GetRemotingSigningDigest(xmlDocument, new RemoteSignatureParameters
		{
			PublicCertificate = publicCertificate,
			SignaturePackaging = packaging,
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = packaging == SignaturePackaging.InternallyDetached
				? "test"
				: null,
		}, out byte[] digestValue);

		Assert.IsNotNull(signatureDocument);
		Assert.IsNotNull(signatureDocument.XadesSignature);

		if (packaging != SignaturePackaging.Enveloping)
		{
			Assert.IsNotNull(signatureDocument.Document);
		}

		// Sign digest
		var asymmetricSignatureFormatter = new RSAPKCS1SignatureFormatter(certificate.GetRSAPrivateKey());
		asymmetricSignatureFormatter.SetHashAlgorithm(HashAlgorithmName.SHA256.Name);
		byte[] signatureValue = asymmetricSignatureFormatter.CreateSignature(digestValue);

		// Attach signature
		signatureDocument = service.AttachSignature(signatureDocument, signatureValue);

		AssertValid(signatureDocument);
	}
}
