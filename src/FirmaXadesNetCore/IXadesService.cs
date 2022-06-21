// --------------------------------------------------------------------------------------------------------------------
// XadesService.cs
//
// FirmaXadesNet - Librería para la generación de firmas XADES
// Copyright (C) 2016 Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
//
// This program is free software: you can redistribute it and/or modify
// it under the +terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/. 
//
// E-Mail: informatica@gemuc.es
// 
// --------------------------------------------------------------------------------------------------------------------

using System.Xml;

namespace FirmaXadesNetCore;

/// <summary>
/// Provides a mechanism for working with XAdES signatures.
/// </summary>
public interface IXadesService
{
	/// <summary>
	/// Complete the signing process.
	/// </summary>
	/// <param name="stream"></param>
	/// <param name="parameters"></param>
	SignatureDocument Sign(Stream stream, LocalSignatureParameters parameters);

	/// <summary>
	/// Add a signature to the document
	/// </summary>
	/// <param name="signatureDocument"></param>
	/// <param name="parameters"></param>
	SignatureDocument CoSign(SignatureDocument signatureDocument, LocalSignatureParameters parameters);

	/// <summary>
	/// Performs the countersignature of the current signature
	/// </summary>
	/// <param name="signatureDocument"></param>
	/// <param name="parameters"></param>
	SignatureDocument CounterSign(SignatureDocument signatureDocument, LocalSignatureParameters parameters);

	/// <summary>
	/// Performs a system signing and gets the digest for remote singing.
	/// </summary>
	/// <param name="xmlDocument">the input XML</param>
	/// <param name="parameters">the signing parameters</param>
	/// <param name="digest">the digest</param>
	/// <returns>the signature document</returns>
	SignatureDocument GetRemotingSigningDigest(XmlDocument xmlDocument, RemoteSignatureParameters parameters, out byte[] digest);

	/// <summary>
	/// Performs a co system signing and gets the digest for remote singing.
	/// </summary>
	/// <param name="signatureDocument">the signature to countersign</param>
	/// <param name="parameters">the signing parameters</param>
	/// <param name="digest">the digest</param>
	/// <returns>the signature document</returns>
	SignatureDocument GetCoRemotingSigningDigest(SignatureDocument signatureDocument, RemoteSignatureParameters parameters, out byte[] digest);

	/// <summary>
	/// Performs a counter system signing and gets the digest for remote singing.
	/// </summary>
	/// <param name="signatureDocument">the signature to countersign</param>
	/// <param name="parameters">the signing parameters</param>
	/// <param name="digest">the digest</param>
	/// <returns>the signature document</returns>
	SignatureDocument GetCounterRemotingSigningDigest(SignatureDocument signatureDocument, RemoteSignatureParameters parameters, out byte[] digest);

	/// <summary>
	/// Attaches the signature value to the signature document.
	/// </summary>
	/// <param name="document">the signature document</param>
	/// <param name="signatureValue">the signature value</param>
	/// <returns>the updated signature document</returns>
	SignatureDocument AttachSignature(SignatureDocument document, byte[] signatureValue);

	/// <summary>
	/// Attaches the signature value to the counter signature document.
	/// </summary>
	/// <param name="document">the counter signature document</param>
	/// <param name="signatureValue">the signature value</param>
	/// <returns>the updated counter signature document</returns>
	SignatureDocument AttachCounterSignature(SignatureDocument document, byte[] signatureValue);

	/// <summary>
	/// Loads the signature documents from the specified XML stream.
	/// </summary>
	/// <param name="stream">the XML stream</param>
	/// <returns>the signature documents</returns>
	SignatureDocument[] Load(Stream stream);

	/// <summary>
	/// Loads the signature documents from the specified XML filename.
	/// </summary>
	/// <param name="fileName">the XML file name</param>
	/// <returns>the signature documents</returns>
	SignatureDocument[] Load(string fileName);

	/// <summary>
	/// Loads the signature documents from the specified XML document.
	/// </summary>
	/// <param name="xmlDocument">the XML document</param>
	/// <returns>the signature documents</returns>
	SignatureDocument[] Load(XmlDocument xmlDocument);

	/// <summary>
	/// Validates the signature document with the specified options.
	/// </summary>
	/// <param name="signatureDocument">the signature document</param>
	/// <param name="validationFlags">the validation flags</param>
	/// <param name="validateTimestamps">a flag indicating whether to validate timestamps or not</param>
	/// <returns>the validation result</returns>
	ValidationResult Validate(SignatureDocument signatureDocument, XadesValidationFlags validationFlags, bool validateTimestamps);
}
