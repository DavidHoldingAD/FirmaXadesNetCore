// --------------------------------------------------------------------------------------------------------------------
// XadesValidator.cs
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

using System.Collections;
using System.Security.Cryptography.Xml;
using FirmaXadesNetCore.Signature;
using FirmaXadesNetCore.Utils;
using Microsoft.Xades;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities;

namespace FirmaXadesNetCore.Validation;

internal sealed class XadesValidator
{
	public static ValidationResult Validate(SignatureDocument signatureDocument)
		=> Validate(signatureDocument, XadesValidationFlags.CheckXmldsigSignature, validateTimeStamps: true);

	public static ValidationResult Validate(SignatureDocument signatureDocument, XadesValidationFlags validationFlags, bool validateTimeStamps)
	{
		if (signatureDocument is null)
		{
			throw new ArgumentNullException(nameof(signatureDocument));
		}

		try
		{
			// Check the fingerprints of the references and the signature
			if (!signatureDocument.XadesSignature.CheckSignature(validationFlags))
			{
				return ValidationResult.Invalid("Could not validate signature.");
			}

			if (validateTimeStamps
				&& signatureDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Count > 0)
			{
				if (!ValidateTimestamps(signatureDocument.XadesSignature))
				{
					return ValidationResult.Invalid("The timestamp footprint does not correspond to the calculated one.");
				}
			}

			return ValidationResult.Valid("Successful signature verification.");
		}
		catch (Exception ex)
		{
			return ValidationResult.Invalid($"An error has occurred while validating signature.", ex);
		}
	}

	private static bool ValidateTimestamps(XadesSignedXml xadesSignature)
	{
		TimeStamp[] timestamps = xadesSignature
			.UnsignedProperties
			.UnsignedSignatureProperties
			.SignatureTimeStampCollection
			.OfType<TimeStamp>()
			.ToArray();

		if (timestamps.Length <= 0)
		{
			throw new ArgumentException("No timestamp present in unsigned signature properties.", nameof(xadesSignature));
		}

		foreach (TimeStamp timestamp in timestamps)
		{
			var token = new TimeStampToken(new CmsSignedData(timestamp.EncapsulatedTimeStamp.PkiData));

			byte[] timeStampHash = token.TimeStampInfo.GetMessageImprintDigest();
			var timeStampHashMethod = DigestMethod.GetByOid(token.TimeStampInfo.HashAlgorithm.Algorithm.Id);

			System.Security.Cryptography.Xml.Transform transform = timestamp.CanonicalizationMethod?.Algorithm switch
			{
				SignedXml.XmlDsigC14NTransformUrl
					=> new XmlDsigC14NTransform(),
				SignedXml.XmlDsigC14NWithCommentsTransformUrl
					=> new XmlDsigC14NWithCommentsTransform(),
				SignedXml.XmlDsigExcC14NTransformUrl
					=> new XmlDsigExcC14NTransform(),
				SignedXml.XmlDsigExcC14NWithCommentsTransformUrl
					=> new XmlDsigExcC14NWithCommentsTransform(),
				_
					=> new XmlDsigC14NTransform(),
			};

			var signatureValueElementXpaths = new ArrayList
			{
				"ds:SignatureValue",
			};

			byte[] signatureHash = XmlUtils.ComputeValueOfElementList(xadesSignature, signatureValueElementXpaths, transform);
			byte[] signatureValueHash = timeStampHashMethod.ComputeHash(signatureHash);

			if (!Arrays.AreEqual(timeStampHash, signatureValueHash))
			{
				return false;
			}
		}

		return true;
	}
}
