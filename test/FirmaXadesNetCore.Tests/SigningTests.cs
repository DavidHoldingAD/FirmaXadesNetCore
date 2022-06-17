using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using FirmaXadesNetCore.Signature;
using FirmaXadesNetCore.Signature.Parameters;
using FirmaXadesNetCore.Validation;

namespace FirmaXadesNetCore.Tests;

[TestClass]
public class SigningTests : SigningTestsBase
{
	[TestMethod]
	[DataRow(SignaturePackaging.ENVELOPED)]
	[DataRow(SignaturePackaging.ENVELOPING)]
	[DataRow(SignaturePackaging.INTERNALLY_DETACHED)]
	//[DataRow(SignaturePackaging.EXTERNALLY_DETACHED)]
	public void Sign_Validate(SignaturePackaging packaging)
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

		ValidationResult result = service.Validate(document);

		Assert.IsTrue(result.IsValid);
	}

	[TestMethod]
	[DataRow(SignaturePackaging.ENVELOPED)]
	[DataRow(SignaturePackaging.ENVELOPING)]
	[DataRow(SignaturePackaging.INTERNALLY_DETACHED)]
	//[DataRow(SignaturePackaging.EXTERNALLY_DETACHED)]
	public void Sign_Remote_Validate(SignaturePackaging packaging)
	{
		var service = new XadesService();

		using Stream stream = CreateExampleDocumentStream(elementID: "test");
		using X509Certificate2 certificate = CreateSelfSignedCertificate();
		using var publicCertificate = new X509Certificate2(certificate.Export(X509ContentType.Cert));

		// Get digest
		SignatureDocument document = service.GetRemotingSigningDigest(stream, new RemoteSignatureParameters
		{
			PublicCertificate = publicCertificate,
			SignaturePackaging = packaging,
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = packaging == SignaturePackaging.INTERNALLY_DETACHED
				? "test"
				: null,
		}, out byte[] digestValue);

		// Sign digest
		var asymmetricSignatureFormatter = new RSAPKCS1SignatureFormatter(certificate.GetRSAPrivateKey());
		asymmetricSignatureFormatter.SetHashAlgorithm(HashAlgorithmName.SHA256.Name);
		byte[] signatureValue = asymmetricSignatureFormatter.CreateSignature(digestValue);

		// Attach signature
		service.AttachSignature(document, signatureValue);

		// Verify
		ValidationResult result = service.Validate(document);

		Assert.IsTrue(result.IsValid);
	}
}
