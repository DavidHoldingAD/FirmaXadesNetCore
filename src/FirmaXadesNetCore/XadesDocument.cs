using System.Text;
using System.Xml;
using FirmaXadesNetCore.Clients;
using FirmaXadesNetCore.Upgraders.Parameters;

namespace FirmaXadesNetCore;

/// <summary>
/// Represents a XADES document.
/// </summary>
public sealed class XadesDocument : IXadesDocument
{
	private readonly XmlDocument _document;
	private readonly XadesService _service;
	private readonly XadesUpgraderService _upgraderService;

	/// <summary>
	/// Initializes a new instance of the <see cref="XadesDocument"/> class.
	/// </summary>
	/// <param name="document">the XML document</param>
	/// <exception cref="ArgumentNullException">when document is null</exception>
	public XadesDocument(XmlDocument document)
	{
		_document = document ?? throw new ArgumentNullException(nameof(document));
		_service = new XadesService();
		_upgraderService = new XadesUpgraderService();
	}

	/// <summary>
	/// Creates a new instance of the <see cref="XadesDocument"/> class.
	/// </summary>
	/// <param name="reader">the XML reader</param>
	/// <returns>the created signer</returns>
	/// <exception cref="ArgumentNullException">when reader is null</exception>
	public static XadesDocument Create(XmlReader reader)
	{
		if (reader is null)
		{
			throw new ArgumentNullException(nameof(reader));
		}

		var document = new XmlDocument
		{
			// This should be true if we want the XML to be correctly validated by other programs
			// Example: https://weryfikacjapodpisu.pl/verification/#dropzone
			// Example: https://ec.europa.eu/digital-building-blocks/DSS/webapp-demo/validation
			PreserveWhitespace = true,
		};

		document.Load(reader);

		return new XadesDocument(document);
	}

	/// <summary>
	/// Creates a new instance of the <see cref="XadesDocument"/> class.
	/// </summary>
	/// <param name="stream">the XML stream</param>
	/// <returns>the created signer</returns>
	/// <exception cref="ArgumentNullException">when stream is null</exception>
	public static XadesDocument Create(Stream stream)
	{
		if (stream is null)
		{
			throw new ArgumentNullException(nameof(stream));
		}

		var settings = new XmlReaderSettings
		{
			CloseInput = false,
		};

		using var reader = XmlReader.Create(stream, settings);

		return Create(reader);
	}

	/// <summary>
	/// Creates a new instance of the <see cref="XadesDocument"/> class.
	/// </summary>
	/// <param name="xmlBytes">the XML bytes</param>
	/// <returns>the created signer</returns>
	/// <exception cref="ArgumentNullException">when XML bytes is null</exception>
	public static XadesDocument Create(byte[] xmlBytes)
	{
		if (xmlBytes is null)
		{
			throw new ArgumentNullException(nameof(xmlBytes));
		}

		using var stream = new MemoryStream(xmlBytes);

		return Create(stream);
	}

	#region IXadesDocument Members

	/// <inheritdoc/>
	public SignatureDocument[] GetSignatures()
		=> _service.Load(_document);

	/// <inheritdoc/>
	public byte[] GetDigest(RemoteSignatureParameters parameters,
		out SignatureDocument signatureDocument)
	{
		if (parameters is null)
		{
			throw new ArgumentNullException(nameof(parameters));
		}

		if (parameters.PublicCertificate is null)
		{
			throw new ArgumentException($"Missing required public certificate.", nameof(parameters));
		}

		// Compute digest
		signatureDocument = _service
			.GetRemotingSigningDigest(_document, parameters, out byte[] digestValue);

		return digestValue;
	}

	/// <inheritdoc/>
	public byte[] GetCoSigningDigest(SignatureDocument signatureDocument,
		RemoteSignatureParameters parameters,
		out SignatureDocument coSignatureDocument)
	{
		if (signatureDocument is null)
		{
			throw new ArgumentNullException(nameof(signatureDocument));
		}

		if (parameters is null)
		{
			throw new ArgumentNullException(nameof(parameters));
		}

		if (parameters.PublicCertificate is null)
		{
			throw new ArgumentException($"Missing required public certificate.", nameof(parameters));
		}

		// Compute digest
		coSignatureDocument = _service
			.GetCoRemotingSigningDigest(signatureDocument, parameters, out byte[] digestValue);

		return digestValue;
	}

	/// <inheritdoc/>
	public byte[] GetCounterSigningDigest(SignatureDocument signatureDocument,
		RemoteSignatureParameters parameters,
		out SignatureDocument counterSignatureDocument)
	{
		if (signatureDocument is null)
		{
			throw new ArgumentNullException(nameof(signatureDocument));
		}

		if (parameters is null)
		{
			throw new ArgumentNullException(nameof(parameters));
		}

		if (parameters.PublicCertificate is null)
		{
			throw new ArgumentException($"Missing required public certificate.", nameof(parameters));
		}

		// Compute digest
		counterSignatureDocument = _service
			.GetCounterRemotingSigningDigest(signatureDocument, parameters, out byte[] digestValue);

		return digestValue;
	}

	/// <inheritdoc/>
	public SignatureDocument AttachSignature(SignatureDocument signatureDocument,
		byte[] signatureValue,
		TimestampParameters? timestampParameters = null)
	{
		if (signatureDocument is null)
		{
			throw new ArgumentNullException(nameof(signatureDocument));
		}

		if (signatureValue is null)
		{
			throw new ArgumentNullException(nameof(signatureValue));
		}

		// Updated signature value
		signatureDocument = _service.AttachSignature(signatureDocument, signatureValue);

		// Timestamp
		if (timestampParameters is not null)
		{
			if (timestampParameters.Uri is null)
			{
				throw new Exception($"Missing required timestamp server URI.");
			}

			using TimeStampClient timestampClient = !string.IsNullOrWhiteSpace(timestampParameters.Username)
				&& !string.IsNullOrWhiteSpace(timestampParameters.Password)
					? new TimeStampClient(timestampParameters.Uri, timestampParameters.Username!, timestampParameters.Password!)
					: new TimeStampClient(timestampParameters.Uri);

			var upgradeParameters = new UpgradeParameters(timestampClient)
			{
				DigestMethod = SignatureMethod
					.GetByUri(signatureDocument.XadesSignature!.SignatureMethod)
					.DigestMethod,

				// TODO: CLRs and OCSP servers
			};

			_upgraderService.Upgrade(signatureDocument, SignatureFormat.XadesT, upgradeParameters);
		}

		// Update document element
		XmlNode? signatureElement = _document.SelectSingleNode($"//*[@Id='{signatureDocument.XadesSignature!.Signature.Id}']");
		if (signatureElement is null)
		{
			_document.RemoveAll();
			_document.AppendChild(_document.ImportNode(signatureDocument.Document!.DocumentElement!, deep: true));
		}

		return signatureDocument;
	}

	/// <inheritdoc/>
	public SignatureDocument AttachCounterSignature(SignatureDocument signatureDocument,
		byte[] signatureValue,
		TimestampParameters? timestampParameters = null)
	{
		if (signatureDocument is null)
		{
			throw new ArgumentNullException(nameof(signatureDocument));
		}

		if (signatureValue is null)
		{
			throw new ArgumentNullException(nameof(signatureValue));
		}

		// Updated signature value
		signatureDocument = _service.AttachCounterSignature(signatureDocument, signatureValue);

		// Timestamp
		if (timestampParameters is not null)
		{
			if (timestampParameters.Uri is null)
			{
				throw new Exception($"Missing required timestamp server URI.");
			}

			using TimeStampClient timestampClient = !string.IsNullOrWhiteSpace(timestampParameters.Username)
				&& !string.IsNullOrWhiteSpace(timestampParameters.Password)
					? new TimeStampClient(timestampParameters.Uri, timestampParameters.Username!, timestampParameters.Password!)
					: new TimeStampClient(timestampParameters.Uri);

			var upgradeParameters = new UpgradeParameters(timestampClient)
			{
				DigestMethod = SignatureMethod
					.GetByUri(signatureDocument.XadesSignature!.SignatureMethod)
					.DigestMethod,

				// TODO: CLRs and OCSP servers
			};

			_upgraderService.Upgrade(signatureDocument, SignatureFormat.XadesT, upgradeParameters);
		}

		// Update document element
		_document.RemoveAll();
		_document.AppendChild(_document.ImportNode(signatureDocument.Document!.DocumentElement!, deep: true));

		return signatureDocument;
	}

	/// <inheritdoc/>
	public bool Verify(out string[] errors,
		XadesValidationFlags validationFlags = XadesValidationFlags.AllChecks,
		bool validateTimestamps = true)
	{
		SignatureDocument[] signatureDocuments = _service.Load(_document);
		if (signatureDocuments is null
			|| signatureDocuments.Length <= 0)
		{
			errors = new[] { "No signatures." };
			return false;
		}

		var messages = new List<string>();

		bool result = true;
		foreach (SignatureDocument signatureDocument in signatureDocuments)
		{
			ValidationResult validationResult = _service.Validate(signatureDocument, validationFlags, validateTimestamps);

			if (!validationResult.IsValid)
			{
				if (!string.IsNullOrEmpty(validationResult.Message))
				{
					messages.Add(validationResult.Message);
				}
				result = false;
			}
		}

		errors = messages.ToArray();
		return result;
	}

	/// <inheritdoc/>
	public void WriteTo(Stream stream)
	{
		if (stream is null)
		{
			throw new ArgumentNullException(nameof(stream));
		}

		var settings = new XmlWriterSettings
		{
			CloseOutput = false,
			Encoding = new UTF8Encoding(encoderShouldEmitUTF8Identifier: false),
		};

		using var xmlWriter = XmlWriter.Create(stream, settings);

		_document.WriteTo(xmlWriter);
	}

	#endregion
}
