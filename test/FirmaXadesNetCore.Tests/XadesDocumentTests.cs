using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace FirmaXadesNetCore.Tests;

[TestClass]
public class XadesDocumentTests : TestsBase
{
	private const string FreeTSAUrl = "https://freetsa.org/tsr";

	[TestMethod]
	public void Create_Reader()
	{
		using Stream stream = CreateExampleDocumentStream(elementID: "test");
		using var reader = XmlReader.Create(stream);

		IXadesDocument document = XadesDocument.Create(reader);

		Assert.IsNotNull(document);
	}

	[TestMethod]
	public void Create_Stream()
	{
		using Stream stream = CreateExampleDocumentStream(elementID: "test");

		IXadesDocument document = XadesDocument.Create(stream);

		Assert.IsNotNull(document);
	}

	[TestMethod]
	public void Create_Bytes()
	{
		using MemoryStream stream = CreateExampleDocumentStream(elementID: "test");

		byte[] xmlBytes = stream.ToArray();

		IXadesDocument document = XadesDocument.Create(xmlBytes);

		Assert.IsNotNull(document);
	}

	[TestMethod]
	public void CreateSigned_GetSignatures()
	{
		using Stream stream = CreateExampleDocumentSignedStream(elementID: "test");

		IXadesDocument document = XadesDocument.Create(stream);

		SignatureDocument[] signatureDocuments = document.GetSignatures();

		Assert.IsNotNull(signatureDocuments);
		Assert.IsTrue(signatureDocuments.Length == 1);
	}

	[TestMethod]
	public void CreateSigned_Verify()
	{
		using Stream stream = CreateExampleDocumentSignedStream(elementID: "test");

		IXadesDocument document = XadesDocument.Create(stream);

		bool result = document.Verify(out string[] errors);

		Assert.IsTrue(result);
		Assert.IsNotNull(errors);
		Assert.IsTrue(errors.Length <= 0);
	}

	[TestMethod]
	[DoNotParallelize]
	[DataRow(SignaturePackaging.Enveloped, RemoteSignatureDigestMode.Hashed)]
	[DataRow(SignaturePackaging.Enveloped, RemoteSignatureDigestMode.Raw)]
	[DataRow(SignaturePackaging.Enveloping, RemoteSignatureDigestMode.Hashed)]
	[DataRow(SignaturePackaging.Enveloping, RemoteSignatureDigestMode.Raw)]
	[DataRow(SignaturePackaging.InternallyDetached, RemoteSignatureDigestMode.Hashed)]
	[DataRow(SignaturePackaging.InternallyDetached, RemoteSignatureDigestMode.Raw)]
	public void Sign_Remote_Validate(SignaturePackaging packaging, RemoteSignatureDigestMode digestMode)
	{
		using Stream stream = CreateExampleDocumentStream(elementID: "test");

		IXadesDocument document = XadesDocument.Create(stream);

		using X509Certificate2 certificate = CreateSelfSignedCertificate();
		using var publicCertificate = new X509Certificate2(certificate.Export(X509ContentType.Cert));

		// Get digest
		byte[] digestValue = document.GetDigest(new RemoteSignatureParameters(publicCertificate)
		{
			DigestMode = digestMode,
			SignaturePackaging = packaging,
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = packaging == SignaturePackaging.InternallyDetached
				? "test"
				: null,
		}, out SignatureDocument signatureDocument);

		Assert.IsNotNull(signatureDocument);
		Assert.IsNotNull(signatureDocument.XadesSignature);

		if (packaging != SignaturePackaging.Enveloping)
		{
			Assert.IsNotNull(signatureDocument.Document);
		}

		if (digestMode == RemoteSignatureDigestMode.Raw)
		{
			digestValue = SHA256.Create().ComputeHash(digestValue);
		}
		// Sign digest
		var asymmetricSignatureFormatter = new RSAPKCS1SignatureFormatter(certificate.GetRSAPrivateKey());
		asymmetricSignatureFormatter.SetHashAlgorithm(HashAlgorithmName.SHA256.Name);
		byte[] signatureValue = asymmetricSignatureFormatter.CreateSignature(digestValue);

		// Attach signature
		signatureDocument = document.AttachSignature(signatureDocument, signatureValue, new TimestampParameters
		{
			Uri = new Uri(FreeTSAUrl),
		});

		// Clear stream
		stream.SetLength(0);
		document.WriteTo(stream);
		stream.Seek(0, SeekOrigin.Begin);

		// Reload document
		document = XadesDocument.Create(stream);
		signatureDocument = document.GetSignatures()[0];

		AssertValid(signatureDocument);

		// Decode timestamp
		Microsoft.Xades.Timestamp timeStamp = signatureDocument.XadesSignature.XadesObject.QualifyingProperties
			.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection[0];

		Assert.IsNotNull(timeStamp);
		Assert.IsNotNull(timeStamp.EncapsulatedTimeStamp.PkiData);
#if NET6_0_OR_GREATER
		Assert.IsTrue(Rfc3161TimestampToken.TryDecode(timeStamp.EncapsulatedTimeStamp.PkiData, out Rfc3161TimestampToken timestampToken, out _));
		Assert.IsNotNull(timestampToken);
		Assert.IsNotNull(timestampToken.TokenInfo);
#endif
	}

	[TestMethod]
	[DoNotParallelize]
	[DataRow(SignaturePackaging.Enveloped, RemoteSignatureDigestMode.Hashed)]
	[DataRow(SignaturePackaging.Enveloped, RemoteSignatureDigestMode.Raw)]
	[DataRow(SignaturePackaging.Enveloping, RemoteSignatureDigestMode.Hashed)]
	[DataRow(SignaturePackaging.Enveloping, RemoteSignatureDigestMode.Raw)]
	[DataRow(SignaturePackaging.InternallyDetached, RemoteSignatureDigestMode.Hashed)]
	[DataRow(SignaturePackaging.InternallyDetached, RemoteSignatureDigestMode.Raw)]
	public void Sign_Co_Remote_Validate(SignaturePackaging packaging, RemoteSignatureDigestMode digestMode)
	{
		if (packaging != SignaturePackaging.InternallyDetached)
		{
			Assert.Inconclusive($"Co signing `{packaging}` packaging is not supported at the moment.");
		}

		using Stream stream = CreateExampleDocumentSignedStream(elementID: "test",
			packaging,
			digestMethodUri: SignedXml.XmlDsigSHA256Url,
			signatureMethodUri: SignedXml.XmlDsigRSASHA256Url);

		IXadesDocument document = XadesDocument.Create(stream);

		SignatureDocument originalSignatureDocument = document.GetSignatures()[0];

		Assert.IsNotNull(originalSignatureDocument);

		using X509Certificate2 certificate = CreateSelfSignedCertificate();
		using var publicCertificate = new X509Certificate2(certificate.Export(X509ContentType.Cert));

		// Get digest
		byte[] digestValue = document.GetCoSigningDigest(originalSignatureDocument, new RemoteSignatureParameters(publicCertificate)
		{
			DigestMode = digestMode,
			SignaturePackaging = packaging,
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = packaging == SignaturePackaging.InternallyDetached
				? "test"
				: null,
			DigestMethod = DigestMethod.SHA256,
			SignatureMethod = SignatureMethod.RSAwithSHA256,
		}, out SignatureDocument signatureDocument);

		Assert.IsNotNull(signatureDocument);
		Assert.IsNotNull(signatureDocument.XadesSignature);

		if (packaging != SignaturePackaging.Enveloping)
		{
			Assert.IsNotNull(signatureDocument.Document);
		}

		if (digestMode == RemoteSignatureDigestMode.Raw)
		{
			digestValue = SHA256.Create().ComputeHash(digestValue);
		}

		// Sign digest
		var asymmetricSignatureFormatter = new RSAPKCS1SignatureFormatter(certificate.GetRSAPrivateKey());
		asymmetricSignatureFormatter.SetHashAlgorithm(HashAlgorithmName.SHA256.Name);
		byte[] signatureValue = asymmetricSignatureFormatter.CreateSignature(digestValue);

		// Attach signature
		signatureDocument = document.AttachSignature(signatureDocument, signatureValue, new TimestampParameters
		{
			Uri = new Uri(FreeTSAUrl),
		});

		// Clear stream
		stream.SetLength(0);
		document.WriteTo(stream);
		stream.Seek(0, SeekOrigin.Begin);

		// Reload document
		document = XadesDocument.Create(stream);
		signatureDocument = document.GetSignatures()[1];

		AssertValid(signatureDocument);

		// Decode timestamp
		Microsoft.Xades.Timestamp timeStamp = signatureDocument.XadesSignature.XadesObject.QualifyingProperties
			.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection[0];

		Assert.IsNotNull(timeStamp);
		Assert.IsNotNull(timeStamp.EncapsulatedTimeStamp.PkiData);
#if NET6_0_OR_GREATER
		Assert.IsTrue(Rfc3161TimestampToken.TryDecode(timeStamp.EncapsulatedTimeStamp.PkiData, out Rfc3161TimestampToken timestampToken, out _));
		Assert.IsNotNull(timestampToken);
		Assert.IsNotNull(timestampToken.TokenInfo);
#endif
	}

	[TestMethod]
	[DoNotParallelize]
	[DataRow(SignaturePackaging.Enveloped, RemoteSignatureDigestMode.Hashed)]
	[DataRow(SignaturePackaging.Enveloped, RemoteSignatureDigestMode.Raw)]
	[DataRow(SignaturePackaging.Enveloping, RemoteSignatureDigestMode.Hashed)]
	[DataRow(SignaturePackaging.Enveloping, RemoteSignatureDigestMode.Raw)]
	[DataRow(SignaturePackaging.InternallyDetached, RemoteSignatureDigestMode.Hashed)]
	[DataRow(SignaturePackaging.InternallyDetached, RemoteSignatureDigestMode.Raw)]
	public void Sign_Counter_Remote_Validate(SignaturePackaging packaging, RemoteSignatureDigestMode digestMode)
	{
		using Stream stream = CreateExampleDocumentSignedStream(elementID: "test");

		IXadesDocument document = XadesDocument.Create(stream);

		SignatureDocument originalSignatureDocument = document.GetSignatures()[0];

		Assert.IsNotNull(originalSignatureDocument);

		using X509Certificate2 certificate = CreateSelfSignedCertificate();
		using var publicCertificate = new X509Certificate2(certificate.Export(X509ContentType.Cert));

		// Get digest
		byte[] digestValue = document.GetCounterSigningDigest(originalSignatureDocument, new RemoteSignatureParameters(publicCertificate)
		{
			DigestMode = digestMode,
			SignaturePackaging = packaging,
			DataFormat = new DataFormat { MimeType = "text/xml" },
			ElementIdToSign = packaging == SignaturePackaging.InternallyDetached
				? "test"
				: null,
		}, out SignatureDocument signatureDocument);

		Assert.IsNotNull(signatureDocument);
		Assert.IsNotNull(signatureDocument.XadesSignature);

		if (packaging != SignaturePackaging.Enveloping)
		{
			Assert.IsNotNull(signatureDocument.Document);
		}

		if (digestMode == RemoteSignatureDigestMode.Raw)
		{
			digestValue = SHA256.Create().ComputeHash(digestValue);
		}

		// Sign digest
		var asymmetricSignatureFormatter = new RSAPKCS1SignatureFormatter(certificate.GetRSAPrivateKey());
		asymmetricSignatureFormatter.SetHashAlgorithm(HashAlgorithmName.SHA256.Name);
		byte[] signatureValue = asymmetricSignatureFormatter.CreateSignature(digestValue);

		// Attach signature
		signatureDocument = document.AttachCounterSignature(signatureDocument, signatureValue, new TimestampParameters
		{
			Uri = new Uri(FreeTSAUrl),
		});

		// Clear stream
		stream.SetLength(0);
		document.WriteTo(stream);
		stream.Seek(0, SeekOrigin.Begin);

		// Reload document
		document = XadesDocument.Create(stream);
		signatureDocument = document.GetSignatures()[1];

		AssertValid(signatureDocument);

		// Decode timestamp
		Microsoft.Xades.Timestamp timeStamp = signatureDocument.XadesSignature.XadesObject.QualifyingProperties
			.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection[0];

		Assert.IsNotNull(timeStamp);
		Assert.IsNotNull(timeStamp.EncapsulatedTimeStamp.PkiData);
#if NET6_0_OR_GREATER
		Assert.IsTrue(Rfc3161TimestampToken.TryDecode(timeStamp.EncapsulatedTimeStamp.PkiData, out Rfc3161TimestampToken timestampToken, out _));
		Assert.IsNotNull(timestampToken);
		Assert.IsNotNull(timestampToken.TokenInfo);
#endif
	}
}
