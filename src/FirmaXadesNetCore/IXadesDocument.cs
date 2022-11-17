namespace FirmaXadesNetCore;

/// <summary>
/// Provides a mechanism for working with XAdES XML documents.
/// </summary>
public interface IXadesDocument
{
	/// <summary>
	/// Gets the signatures.
	/// </summary>
	/// <returns>an enumeration of signature documents</returns>
	SignatureDocument[] GetSignatures();

	/// <summary>
	/// Performs a local signing.
	/// </summary>
	/// <param name="parameters">the signing parameters</param>
	/// <returns>the signature document</returns>
	SignatureDocument Sign(LocalSignatureParameters parameters);

	/// <summary>
	/// Gets the digest for the specified signing parameters.
	/// </summary>
	/// <param name="parameters">the signing parameters</param>
	/// <param name="signatureDocument">the signature document</param>
	/// <returns>the digest value</returns>
	byte[] GetDigest(RemoteSignatureParameters parameters,
		out SignatureDocument signatureDocument);

	/// <summary>
	/// Performs a co system signing and gets the digest for remote singing.
	/// </summary>
	/// <param name="signatureDocument">the signature to countersign</param>
	/// <param name="parameters">the signing parameters</param>
	/// <param name="coSignatureDocument">the co signature document</param>
	/// <returns>the digest</returns>>
	byte[] GetCoSigningDigest(SignatureDocument signatureDocument,
		RemoteSignatureParameters parameters,
		out SignatureDocument coSignatureDocument);

	/// <summary>
	/// Performs a counter system signing and gets the digest for remote singing.
	/// </summary>
	/// <param name="signatureDocument">the signature to countersign</param>
	/// <param name="parameters">the signing parameters</param>
	/// <param name="counterSignatureDocument">the counter signature document</param>
	/// <returns>the digest</returns>
	byte[] GetCounterSigningDigest(SignatureDocument signatureDocument,
		RemoteSignatureParameters parameters,
		out SignatureDocument counterSignatureDocument);

	/// <summary>
	/// Attaches the specified signature value.
	/// </summary>
	/// <param name="signatureDocument">the signature document</param>
	/// <param name="signatureValue">the signature value</param>
	/// <param name="timeStampParameters">the timestamp parameters</param>
	/// <returns>the attached signature document</returns>
	SignatureDocument AttachSignature(SignatureDocument signatureDocument,
		byte[] signatureValue,
		TimestampParameters? timeStampParameters = null);

	/// <summary>
	/// Attaches the signature value to the counter signature document.
	/// </summary>
	/// <param name="document">the counter signature document</param>
	/// <param name="signatureValue">the signature value</param>
	/// <param name="timeStampParameters">the timestamp parameters</param>
	/// <returns>the updated counter signature document</returns>
	SignatureDocument AttachCounterSignature(SignatureDocument document,
		byte[] signatureValue,
		TimestampParameters? timeStampParameters = null);

	/// <summary>
	/// Verifies the document signatures.
	/// </summary>
	/// <param name="errors">the errors</param>
	/// <param name="validationFlags">the validation flags</param>
	/// <param name="validateTimestamps">a flag indicating whether to validate the timestamps or not</param>
	/// <returns></returns>
	bool Verify(out string[] errors,
		XadesValidationFlags validationFlags = XadesValidationFlags.AllChecks,
		bool validateTimestamps = true);

	/// <summary>
	/// Serializes the XML document to the specified stream.
	/// </summary>
	/// <param name="stream">the stream</param>
	void WriteTo(Stream stream);
}
