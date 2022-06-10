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
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using FirmaXadesNetCore.Signature;
using FirmaXadesNetCore.Utils;
using Microsoft.Xades;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.Utilities;

namespace FirmaXadesNetCore.Validation;

class XadesValidator
{
	#region Public methods

	public ValidationResult Validate(SignatureDocument sigDocument)
	{
		//The elements that are validated are:
		//* 1. The fingerprints of the firm's references.
		//* 2. The fingerprint of the SignedInfo element is checked and the signature is verified with the public key of the certificate.
		//* 3. If the signature contains a time stamp, it is verified that the fingerprint of the signature coincides with that of the time stamp.
		//* The validation of -C, -X, -XL and -A profiles is outside the scope of this project.
		var result = new ValidationResult();

		try
		{
			// Check the fingerprints of the references and the signature
			sigDocument.XadesSignature.CheckXmldsigSignature();
		}
		catch (Exception ex)
		{
			result.IsValid = false;
			result.Message = $"Signature verification was unsuccessful. Exception: {ex.Message}";

			return result;
		}

		if (sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Count > 0)
		{
			// The timestamp is checked
			TimeStamp timeStamp = sigDocument.XadesSignature.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection[0];
			var token = new TimeStampToken(new CmsSignedData(timeStamp.EncapsulatedTimeStamp.PkiData));

			byte[] tsHashValue = token.TimeStampInfo.GetMessageImprintDigest();
			var tsDigestMethod = Crypto.DigestMethod.GetByOid(token.TimeStampInfo.HashAlgorithm.Algorithm.Id);

			System.Security.Cryptography.Xml.Transform transform;
			if (timeStamp.CanonicalizationMethod != null)
			{
				transform = CryptoConfig.CreateFromName(timeStamp.CanonicalizationMethod.Algorithm) as System.Security.Cryptography.Xml.Transform;
			}
			else
			{
				transform = new XmlDsigC14NTransform();
			}

			var signatureValueElementXpaths = new ArrayList
			{
				"ds:SignatureValue",
			};

			byte[] signatureValueHash = DigestUtil
				.ComputeHashValue(XMLUtil.ComputeValueOfElementList(sigDocument.XadesSignature, signatureValueElementXpaths, transform), tsDigestMethod);

			if (!Arrays.AreEqual(tsHashValue, signatureValueHash))
			{
				result.IsValid = false;
				result.Message = "The time stamp footprint does not correspond to the calculated one.";

				return result;
			}
		}

		result.IsValid = true;
		result.Message = "Successful signature verification.";

		return result;
	}

	#endregion
}
