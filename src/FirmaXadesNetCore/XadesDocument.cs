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

		var document = new XmlDocument
		{
			// This should be true if we want the XML to be correctly validated by other programs
			// Example: https://weryfikacjapodpisu.pl/verification/#dropzone
			PreserveWhitespace = true,
		};

		document.Load(reader);

		return new XadesDocument(document);
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
	public SignatureDocument AttachSignature(SignatureDocument signatureDocument,
		byte[] signatureValue,
		TimeStampParameters timeStampParameters = null)
	{
		if (signatureDocument is null)
		{
			throw new ArgumentNullException(nameof(signatureDocument));
		}

		if (signatureValue is null)
		{
			throw new ArgumentNullException(nameof(signatureValue));
		}

		// Enveloping mode clones the original XML document
		bool updateAfterAttach = signatureDocument.Document is null;

		// Updated signature value
		signatureDocument = _service.AttachSignature(signatureDocument, signatureValue);

		// Timestamp
		if (timeStampParameters is not null)
		{
			using TimeStampClient timestampClient = !string.IsNullOrWhiteSpace(timeStampParameters.Username)
				&& !string.IsNullOrWhiteSpace(timeStampParameters.Password)
					? new TimeStampClient(timeStampParameters.Uri, timeStampParameters.Username, timeStampParameters.Password)
					: new TimeStampClient(timeStampParameters.Uri);

			var upgradeParameters = new UpgradeParameters
			{
				TimeStampClient = timestampClient,
				DigestMethod = SignatureMethod
					.GetByUri(signatureDocument.XadesSignature.SignatureMethod)
					.DigestMethod,

				// TODO: CLRs and OCSP servers
			};

			_upgraderService.Upgrade(signatureDocument, SignatureFormat.XadesT, upgradeParameters);
		}

		// Enveloping
		if (updateAfterAttach)
		{
			_document.RemoveAll();
			_document.AppendChild(_document.ImportNode(signatureDocument.XadesSignature.GetXml(), deep: true));
		}

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
