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

#if NET6_0_OR_GREATER
using System.Collections;
using System.Net.Http;
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

/// <summary>
/// Represents a OCSP client.
/// </summary>
public class OcspClient
{
	private static readonly HttpClient _httpClient;
	private Asn1OctetString? _nonceAsn1OctetString;

	static OcspClient()
	{
		_httpClient = new HttpClient();
		_httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/ocsp-response"));
	}

	/// <summary>
	/// Method that checks the status of a certificate.
	/// </summary>
	/// <param name="eeCert"></param>
	/// <param name="issuerCert"></param>
	/// <param name="url"></param>
	/// <param name="requestorName"></param>
	/// <param name="signCertificate"></param>
	/// <returns></returns>
	public byte[] QueryBinary(X509Certificate eeCert,
		X509Certificate issuerCert,
		string url,
		GeneralName? requestorName = null,
		System.Security.Cryptography.X509Certificates.X509Certificate2? signCertificate = null)
	{
		if (eeCert is null)
		{
			throw new ArgumentNullException(nameof(eeCert));
		}

		if (issuerCert is null)
		{
			throw new ArgumentNullException(nameof(issuerCert));
		}

		if (url is null)
		{
			throw new ArgumentNullException(nameof(url));
		}

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
	/// Returns the URL of the OCSP server that contains the certificate.
	/// </summary>
	/// <param name="certificate"></param>
	/// <returns></returns>
	public string? GetAuthorityInformationAccessOcspUrl(X509Certificate certificate)
	{
		if (certificate is null)
		{
			throw new ArgumentNullException(nameof(certificate));
		}

		var ocspUrls = new List<string>();

		try
		{
			Asn1Object? obj = GetExtensionValue(certificate, X509Extensions.AuthorityInfoAccess.Id);
			if (obj is null)
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
	/// Processes the response from the OCSP server and returns the status of the certificate.
	/// </summary>
	/// <param name="binaryResp"></param>
	/// <returns></returns>
	public CertificateStatus ProcessOcspResponse(byte[] binaryResp)
	{
		if (binaryResp is null)
		{
			throw new ArgumentNullException(nameof(binaryResp));
		}

		if (_nonceAsn1OctetString is null)
		{
			throw new InvalidOperationException($"Request must be generated before processing.");
		}

		if (binaryResp.Length <= 0)
		{
			return CertificateStatus.Unknown;
		}

		var ocspResponse = new OcspResp(binaryResp);
		if (ocspResponse.Status != OcspRespStatus.Successful)
		{
			throw new Exception($"Unknown status `{ocspResponse.Status}`.");
		}

		var basicOscpResponse = (BasicOcspResp)ocspResponse.GetResponseObject();
		if (basicOscpResponse.GetExtensionValue(OcspObjectIdentifiers.PkixOcspNonce).ToString()
			!= _nonceAsn1OctetString.ToString())
		{
			throw new Exception("Bad nonce value");
		}

		if (basicOscpResponse.Responses.Length != 1)
		{
			return CertificateStatus.Unknown;
		}

		object ocspCertificateStatus = basicOscpResponse.Responses[0].GetCertStatus();
		if (ocspCertificateStatus == Org.BouncyCastle.Ocsp.CertificateStatus.Good)
		{
			return CertificateStatus.Good;
		}
		else if (ocspCertificateStatus is RevokedStatus)
		{
			return CertificateStatus.Revoked;
		}
		else if (ocspCertificateStatus is UnknownStatus)
		{
			return CertificateStatus.Unknown;
		}
		else
		{
			return CertificateStatus.Unknown;
		}
	}

	private OcspReq GenerateOcspRequest(X509Certificate issuerCert,
		BigInteger serialNumber,
		GeneralName? requestorName,
		System.Security.Cryptography.X509Certificates.X509Certificate2? signCertificate)
	{
		var id = new CertificateID(CertificateID.HashSha1, issuerCert, serialNumber);

		return GenerateOcspRequest(id, requestorName, signCertificate);
	}

	private OcspReq GenerateOcspRequest(CertificateID id,
		GeneralName? requestorName,
		System.Security.Cryptography.X509Certificates.X509Certificate2? signCertificate)
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
			return ocspRequestGenerator.Generate(RSA_CERTIFICATE_EXTENSIONS.GetRSAPrivateKey(signCertificate)!, CertificateUtils.GetCertificateChain(signCertificate));
		}
		else
		{
			return ocspRequestGenerator.Generate();
		}
	}

	private static Asn1Object? GetExtensionValue(X509Certificate certificate, string oid)
	{
		byte[] bytes = certificate.GetExtensionValue(new DerObjectIdentifier(oid)).GetOctets();

		if (bytes is null)
		{
			return null;
		}

		var aIn = new Asn1InputStream(bytes);

		return aIn.ReadObject();
	}
}
#endif
