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
	/// Gets the digest for the specified signing parameters.
	/// </summary>
	/// <param name="parameters">the signing parameters</param>
	/// <param name="signatureDocument">the signature document</param>
	/// <returns>the digest value</returns>
	byte[] GetDigest(RemoteSignatureParameters parameters,
		out SignatureDocument signatureDocument);

	/// <summary>
	/// Attaches the specified signature value.
	/// </summary>
	/// <param name="signatureDocument">the signature document</param>
	/// <param name="signatureValue">the signature value</param>
	/// <param name="timeStampParameters">the timestamp parameters</param>
	/// <returns>the attached signature document</returns>
	SignatureDocument AttachSignature(SignatureDocument signatureDocument,
		byte[] signatureValue,
		TimeStampParameters timeStampParameters = null);

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
