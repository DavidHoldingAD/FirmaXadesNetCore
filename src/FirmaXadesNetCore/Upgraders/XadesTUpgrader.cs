// --------------------------------------------------------------------------------------------------------------------
// XadesTUpgrader.cs
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
using FirmaXadesNetCore.Upgraders.Parameters;
using FirmaXadesNetCore.Utils;
using Microsoft.Xades;

namespace FirmaXadesNetCore.Upgraders;

internal sealed class XadesTUpgrader : IXadesUpgrader
{
	#region IXadesUpgrader Members

	/// <inheritdoc/>
	public void Upgrade(SignatureDocument signatureDocument, UpgradeParameters parameters)
	{
		if (signatureDocument is null)
		{
			throw new ArgumentNullException(nameof(signatureDocument));
		}

		if (parameters is null)
		{
			throw new ArgumentNullException(nameof(parameters));
		}

		try
		{
			UnsignedProperties unsignedProperties = signatureDocument.XadesSignature!.UnsignedProperties;
			if (unsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Count > 0)
			{
				throw new Exception("The signature already contains a timestamp.");
			}

			var excTransform = new XmlDsigExcC14NTransform();
			var signatureValueElementXpaths = new ArrayList
			{
				"ds:SignatureValue",
			};

			byte[] signatureValueHash = parameters.DigestMethod
				.ComputeHash(XmlUtils.ComputeValueOfElementList(signatureDocument.XadesSignature, signatureValueElementXpaths, excTransform));

			byte[] timestampData = parameters.TimestampClient
				.GetTimeStampAsync(signatureValueHash, parameters.DigestMethod, true, CancellationToken.None)
				.ConfigureAwait(continueOnCapturedContext: false)
				.GetAwaiter()
				.GetResult();

			var signatureTimeStamp = new Timestamp("SignatureTimeStamp")
			{
				Id = $"SignatureTimeStamp-{signatureDocument.XadesSignature.Signature.Id}",
				CanonicalizationMethod = new CanonicalizationMethod
				{
					Algorithm = excTransform.Algorithm
				}
			};

			if (signatureTimeStamp.EncapsulatedTimeStamp is not null)
			{
				signatureTimeStamp.EncapsulatedTimeStamp.PkiData = timestampData;
				signatureTimeStamp.EncapsulatedTimeStamp.Id = $"SignatureTimeStamp-{Guid.NewGuid()}";
			}

			unsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Add(signatureTimeStamp);

			signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;
			signatureDocument.UpdateDocument();
		}
		catch (Exception ex)
		{
			throw new Exception("An error occurred while inserting the timestamp.", ex);
		}
	}

	#endregion
}
