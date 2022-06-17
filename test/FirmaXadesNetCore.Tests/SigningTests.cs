using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using FirmaXadesNetCore.Signature;
using FirmaXadesNetCore.Signature.Parameters;
using FirmaXadesNetCore.Validation;

namespace FirmaXadesNetCore.Tests;

[TestClass]
public class SigningTests : SigningTestsBase
{
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

		SignatureDocument document = service.Sign(stream, new SignatureParameters
		{
			SignaturePackaging = SignaturePackaging.ENVELOPED,
			Signer = new Crypto.Signer(certificate),
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = "test",
			DigestMethod = Crypto.DigestMethod.GetByUri(digestMethod),
			SignatureMethod = Crypto.SignatureMethod.GetByUri(signatureMethod),
		});

		// Verify
		ValidationResult result = service.Validate(document, Microsoft.Xades.XadesValidationFlags.AllChecks, validateTimeStamp: true);
		Assert.IsTrue(result.IsValid);
	}

	[TestMethod]
	[DataRow(SignaturePackaging.ENVELOPED)]
	[DataRow(SignaturePackaging.ENVELOPING)]
	[DataRow(SignaturePackaging.INTERNALLY_DETACHED)]
	public void Sign_Packaging_Validate(SignaturePackaging packaging)
	{
		var service = new XadesService();

		using Stream stream = CreateExampleDocumentStream(elementID: "test");
		using X509Certificate2 certificate = CreateSelfSignedCertificate();

		SignatureDocument document = service.Sign(stream, new SignatureParameters
		{
			SignaturePackaging = packaging,
			Signer = new Crypto.Signer(certificate),
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = packaging == SignaturePackaging.INTERNALLY_DETACHED
				? "test"
				: null,
		});

		// Verify
		ValidationResult result = service.Validate(document, Microsoft.Xades.XadesValidationFlags.AllChecks, validateTimeStamp: true);
		Assert.IsTrue(result.IsValid);
	}

	[TestMethod]
	[DataRow(SignaturePackaging.ENVELOPED)]
	[DataRow(SignaturePackaging.ENVELOPING)]
	[DataRow(SignaturePackaging.INTERNALLY_DETACHED)]
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
		SignatureDocument document = service.GetRemotingSigningDigest(xmlDocument, new RemoteSignatureParameters
		{
			PublicCertificate = publicCertificate,
			SignaturePackaging = packaging,
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = packaging == SignaturePackaging.INTERNALLY_DETACHED
				? "test"
				: null,
		}, out byte[] digestValue);

		Assert.IsNotNull(document);
		Assert.IsNotNull(document.XadesSignature);

		if (packaging != SignaturePackaging.ENVELOPING)
		{
			Assert.IsNotNull(document.Document);
		}

		// Sign digest
		var asymmetricSignatureFormatter = new RSAPKCS1SignatureFormatter(certificate.GetRSAPrivateKey());
		asymmetricSignatureFormatter.SetHashAlgorithm(HashAlgorithmName.SHA256.Name);
		byte[] signatureValue = asymmetricSignatureFormatter.CreateSignature(digestValue);

		// Attach signature
		service.AttachSignature(document, signatureValue);

		// Verify
		ValidationResult result = service.Validate(document, Microsoft.Xades.XadesValidationFlags.AllChecks, validateTimeStamp: true);
		Assert.IsTrue(result.IsValid);
	}
}
