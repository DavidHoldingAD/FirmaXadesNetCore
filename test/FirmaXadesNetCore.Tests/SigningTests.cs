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
}
