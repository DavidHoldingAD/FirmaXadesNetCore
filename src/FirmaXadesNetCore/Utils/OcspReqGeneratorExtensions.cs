﻿// --------------------------------------------------------------------------------------------------------------------
// DotNetOcspReqGenerator.cs
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
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.Pkcs;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Ocsp;

namespace FirmaXadesNetCore.Utils;

/// <summary>
/// The OcspReqGenerator class is extended.
/// </summary>
static class OcspReqGeneratorExtensions
{
	public static OcspReq Generate(this OcspReqGenerator ocspRegGenerator, RSA rsa, X509Chain? chain)
	{
		if (ocspRegGenerator is null)
		{
			throw new ArgumentNullException(nameof(ocspRegGenerator));
		}

		if (rsa is null)
		{
			throw new ArgumentNullException(nameof(rsa));
		}

		var requests = new Asn1EncodableVector();

		IList list = ReflectionUtils.GetOcspReqGeneratorList(ocspRegGenerator);

		foreach (object reqObj in list)
		{
			try
			{
				requests.Add(ReflectionUtils.OcspReqGeneratorInfoRequestToRequest(reqObj));
			}
			catch (Exception e)
			{
				throw new OcspException("exception creating Request", e);
			}
		}

		GeneralName requestorName = ReflectionUtils.GetOcspReqGeneratorInfoRequestorName(ocspRegGenerator);

		if (requestorName is null)
		{
			throw new OcspException("requestorName must be specified if request is signed.");
		}

		X509Extensions requestExtensions = ReflectionUtils.GetOcspReqGeneratorInfoRequestExtensions(ocspRegGenerator);

		var tbsReq = new TbsRequest(requestorName, new DerSequence(requests), requestExtensions);

		DerObjectIdentifier signingAlgorithm = PkcsObjectIdentifiers.Sha1WithRsaEncryption;

		if (signingAlgorithm is null)
		{
			return new OcspReq(new OcspRequest(tbsReq, null));
		}


		DerBitString bitSig;
		try
		{
			byte[] encoded = tbsReq.GetEncoded();
			byte[] signedData = rsa.SignData(encoded, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

			bitSig = new DerBitString(signedData);
		}
		catch (Exception e)
		{
			throw new OcspException($"An error has occurred while processing timestamp request.", e);
		}

		var sigAlgId = new AlgorithmIdentifier(signingAlgorithm, DerNull.Instance);

		Signature? signature;
		if (chain != null && chain.ChainElements.Count > 0)
		{
			var v = new Asn1EncodableVector();
			try
			{
				for (int i = 0; i != chain.ChainElements.Count; i++)
				{
					v.Add(
						X509CertificateStructure.GetInstance(
							Asn1Object.FromByteArray(chain.ChainElements[i].Certificate.RawData)));
				}
			}
			catch (Exception e)
			{
				throw new OcspException("error processing certs", e);
			}

			signature = new Signature(sigAlgId, bitSig, new DerSequence(v));
		}
		else
		{
			signature = new Signature(sigAlgId, bitSig);
		}

		return new OcspReq(new OcspRequest(tbsReq, signature));
	}
}
