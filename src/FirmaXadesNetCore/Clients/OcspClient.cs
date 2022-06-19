// --------------------------------------------------------------------------------------------------------------------
// OcspClient.cs
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
using System.Net.Http.Headers;
using FirmaXadesNetCore.Utils;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.X509;
using RSA_CERTIFICATE_EXTENSIONS = System.Security.Cryptography.X509Certificates.RSACertificateExtensions;

namespace FirmaXadesNetCore.Clients;

public class OcspClient
{
	private static readonly HttpClient _httpClient;

	static OcspClient()
	{
		_httpClient = new HttpClient();
		_httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/ocsp-response"));
	}

	#region Private variables

	private Asn1OctetString _nonceAsn1OctetString;

	#endregion

	#region Public methods

	/// <summary>
	/// Método que comprueba el estado de un certificado
	/// </summary>
	/// <param name="eeCert"></param>
	/// <param name="issuerCert"></param>
	/// <param name="url"></param>
	/// <returns></returns>
	public byte[] QueryBinary(X509Certificate eeCert, X509Certificate issuerCert, string url, GeneralName requestorName = null,
		System.Security.Cryptography.X509Certificates.X509Certificate2 signCertificate = null)
	{
		OcspReq ocspRequest = GenerateOcspRequest(issuerCert, eeCert.SerialNumber, requestorName, signCertificate);

		using var request = new HttpRequestMessage(HttpMethod.Post, url)
		{
			Content = new ByteArrayContent(ocspRequest.GetEncoded()),
		};

		request.Content.Headers.ContentType = MediaTypeWithQualityHeaderValue.Parse("application/ocsp-request");

		using HttpResponseMessage response = _httpClient.Send(request);

		response.EnsureSuccessStatusCode();

		return response.Content
			.ReadAsByteArrayAsync()
			.ConfigureAwait(continueOnCapturedContext: false)
			.GetAwaiter()
			.GetResult();
	}

	/// <summary>
	/// Devuelve la URL del servidor OCSP que contenga el certificado
	/// </summary>
	/// <param name="cert"></param>
	/// <returns></returns>
	public string GetAuthorityInformationAccessOcspUrl(X509Certificate cert)
	{
		var ocspUrls = new List<string>();

		try
		{
			Asn1Object obj = GetExtensionValue(cert, X509Extensions.AuthorityInfoAccess.Id);

			if (obj == null)
			{
				return null;
			}

			// Switched to manual parse 
			var s = (Asn1Sequence)obj;
			IEnumerator elements = s.GetEnumerator();

			while (elements.MoveNext())
			{
				var element = (Asn1Sequence)elements.Current;
				var oid = (DerObjectIdentifier)element[0];

				if (oid.Id.Equals("1.3.6.1.5.5.7.48.1")) // Is Ocsp? 
				{
					var taggedObject = (Asn1TaggedObject)element[1];
					var gn = GeneralName.GetInstance(taggedObject);
					ocspUrls.Add(DerIA5String.GetInstance(gn.Name).GetString());
				}
			}
		}
		catch
		{
			return null;
		}

		return ocspUrls[0];
	}

	/// <summary>
	/// Procesa la respuesta del servidor OCSP y devuelve el estado del certificado
	/// </summary>
	/// <param name="binaryResp"></param>
	/// <returns></returns>
	public CertificateStatus ProcessOcspResponse(byte[] binaryResp)
	{
		if (binaryResp.Length == 0)
		{
			return CertificateStatus.Unknown;
		}

		var r = new OcspResp(binaryResp);
		CertificateStatus cStatus = CertificateStatus.Unknown;

		if (r.Status == OcspRespStatus.Successful)
		{
			var or = (BasicOcspResp)r.GetResponseObject();

			if (or.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce).ToString() !=
				_nonceAsn1OctetString.ToString())
			{
				throw new Exception("Bad nonce value");
			}

			if (or.Responses.Length == 1)
			{
				SingleResp resp = or.Responses[0];

				object certificateStatus = resp.GetCertStatus();

				if (certificateStatus == Org.BouncyCastle.Ocsp.CertificateStatus.Good)
				{
					cStatus = CertificateStatus.Good;
				}
				else if (certificateStatus is RevokedStatus)
				{
					cStatus = CertificateStatus.Revoked;
				}
				else if (certificateStatus is UnknownStatus)
				{
					cStatus = CertificateStatus.Unknown;
				}
			}

		}
		else
		{
			throw new Exception("Unknow status '" + r.Status + "'.");
		}

		return cStatus;
	}

	#endregion

	#region Private methods


	protected static Asn1Object GetExtensionValue(X509Certificate certificate, string oid)
	{
		if (certificate == null)
		{
			return null;
		}

		byte[] bytes = certificate.GetExtensionValue(new DerObjectIdentifier(oid)).GetOctets();

		if (bytes == null)
		{
			return null;
		}

		var aIn = new Asn1InputStream(bytes);

		return aIn.ReadObject();
	}


	private OcspReq GenerateOcspRequest(X509Certificate issuerCert, BigInteger serialNumber, GeneralName requestorName,
		System.Security.Cryptography.X509Certificates.X509Certificate2 signCertificate)
	{
		var id = new CertificateID(CertificateID.HashSha1, issuerCert, serialNumber);
		return GenerateOcspRequest(id, requestorName, signCertificate);
	}

	private OcspReq GenerateOcspRequest(CertificateID id, GeneralName requestorName,
		System.Security.Cryptography.X509Certificates.X509Certificate2 signCertificate)
	{
		var ocspRequestGenerator = new OcspReqGenerator();

		ocspRequestGenerator.AddRequest(id);

		if (requestorName != null)
		{
			ocspRequestGenerator.SetRequestorName(requestorName);
		}

		var oids = new ArrayList();
		var values = new Hashtable();

		oids.Add(OcspObjectIdentifiers.PkixOcspNonce);

		_nonceAsn1OctetString = new DerOctetString(new DerOctetString(BigInteger.ValueOf(DateTime.Now.Ticks).ToByteArray()));

		values.Add(OcspObjectIdentifiers.PkixOcspNonce, new X509Extension(false, _nonceAsn1OctetString));
		ocspRequestGenerator.SetRequestExtensions(new X509Extensions(oids, values));

		if (signCertificate != null)
		{
			return ocspRequestGenerator.Generate(RSA_CERTIFICATE_EXTENSIONS.GetRSAPrivateKey(signCertificate), CertificateUtils.GetCertChain(signCertificate));
		}
		else
		{
			return ocspRequestGenerator.Generate();
		}
	}

	#endregion
}
