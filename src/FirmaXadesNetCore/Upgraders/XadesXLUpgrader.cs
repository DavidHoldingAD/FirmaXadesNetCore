// --------------------------------------------------------------------------------------------------------------------
// XadesXLUpgrader.cs
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
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using FirmaXadesNetCore.Clients;
using FirmaXadesNetCore.Upgraders.Parameters;
using FirmaXadesNetCore.Utils;
using Microsoft.Xades;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Ocsp;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Cms;
using Org.BouncyCastle.Ocsp;
using Org.BouncyCastle.Tsp;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.X509.Extension;
using Org.BouncyCastle.X509.Store;

namespace FirmaXadesNetCore.Upgraders;

internal sealed class XadesXLUpgrader : IXadesUpgrader
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

		using X509Certificate2 signingCertificate = signatureDocument.XadesSignature.GetSigningCertificate();

		UnsignedProperties unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;
		unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs = new CompleteCertificateRefs
		{
			Id = $"CompleteCertificates-{Guid.NewGuid()}",
		};

		unsignedProperties.UnsignedSignatureProperties.CertificateValues = new CertificateValues();
		CertificateValues certificateValues = unsignedProperties.UnsignedSignatureProperties.CertificateValues;
		certificateValues.Id = $"CertificatesValues-{Guid.NewGuid()}";

		unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs = new CompleteRevocationRefs
		{
			Id = $"CompleteRev-{Guid.NewGuid()}",
		};
		unsignedProperties.UnsignedSignatureProperties.RevocationValues = new RevocationValues
		{
			Id = $"RevocationValues-{Guid.NewGuid()}",
		};

		AddCertificate(signingCertificate, unsignedProperties, false, parameters.OcspServers, parameters.Crls, parameters.DigestMethod, parameters.GetOcspUrlFromCertificate);

		AddTSACertificates(unsignedProperties, parameters.OcspServers, parameters.Crls, parameters.DigestMethod, parameters.GetOcspUrlFromCertificate);

		signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;

		TimeStampCertRefs(signatureDocument, parameters);

		signatureDocument.UpdateDocument();
	}

	#endregion

	private string GetResponderName(ResponderID responderId, ref bool byKey)
	{
		var dt = (DerTaggedObject)responderId.ToAsn1Object();

		if (dt.TagNo == 1)
		{
			byKey = false;

			return new X500DistinguishedName(dt.GetObject().GetEncoded()).Name;
		}
		else if (dt.TagNo == 2)
		{
			var tagger = (Asn1TaggedObject)responderId.ToAsn1Object();
			var pubInfo = (Asn1OctetString)tagger.GetObject();
			byKey = true;

			return Convert.ToBase64String(pubInfo.GetOctets());
		}
		else
		{
			return null;
		}
	}

	/// <summary>
	/// Comprueba si dos DN son equivalentes
	/// </summary>
	/// <param name="dn"></param>
	/// <param name="other"></param>
	/// <returns></returns>
	private bool EquivalentDN(X500DistinguishedName dn, X500DistinguishedName other)
		=> X509Name.GetInstance(Asn1Object.FromByteArray(dn.RawData)).Equivalent(X509Name.GetInstance(Asn1Object.FromByteArray(other.RawData)));

	/// <summary>
	/// Determina si un certificado ya ha sido añadido a la colección de certificados
	/// </summary>
	/// <param name="cert"></param>
	/// <param name="unsignedProperties"></param>
	/// <returns></returns>
	private bool CertificateChecked(X509Certificate2 cert, UnsignedProperties unsignedProperties)
	{
		foreach (EncapsulatedX509Certificate item in unsignedProperties.UnsignedSignatureProperties.CertificateValues.EncapsulatedX509CertificateCollection)
		{
			var certItem = new X509Certificate2(item.PkiData);

			if (certItem.Thumbprint == cert.Thumbprint)
			{
				return true;
			}
		}

		return false;
	}

	/// <summary>
	/// Inserta en la lista de certificados el certificado y comprueba la valided del certificado.
	/// </summary>
	/// <param name="cert"></param>
	/// <param name="unsignedProperties"></param>
	/// <param name="addCert"></param>
	/// <param name="ocspServers"></param>
	/// <param name="crlList"></param>
	/// <param name="digestMethod"></param>
	/// <param name="addCertificateOcspUrl"></param>
	/// <param name="extraCerts"></param>
	private void AddCertificate(X509Certificate2 cert, UnsignedProperties unsignedProperties, bool addCert, IEnumerable<OcspServer> ocspServers,
		IEnumerable<X509Crl> crlList, DigestMethod digestMethod, bool addCertificateOcspUrl, X509Certificate2[] extraCerts = null)
	{
		if (addCert)
		{
			if (CertificateChecked(cert, unsignedProperties))
			{
				return;
			}

			string guidCert = Guid.NewGuid().ToString();

			var chainCert = new Cert();
			chainCert.IssuerSerial.X509IssuerName = cert.IssuerName.Name;
			chainCert.IssuerSerial.X509SerialNumber = cert.GetSerialNumberAsDecimalString();
			chainCert.CertDigest.DigestMethod.Algorithm = digestMethod.Uri;
			chainCert.CertDigest.DigestValue = digestMethod.ComputeHash(cert.GetRawCertData());
			chainCert.URI = "#Cert" + guidCert;
			unsignedProperties.UnsignedSignatureProperties.CompleteCertificateRefs.CertRefs.CertCollection.Add(chainCert);

			var encapsulatedX509Certificate = new EncapsulatedX509Certificate
			{
				Id = "Cert" + guidCert,
				PkiData = cert.GetRawCertData()
			};
			unsignedProperties.UnsignedSignatureProperties.CertificateValues.EncapsulatedX509CertificateCollection.Add(encapsulatedX509Certificate);
		}

		X509ChainElementCollection chain = CertificateUtils.GetCertificateChain(cert, extraCerts).ChainElements;

		if (chain.Count > 1)
		{
			X509ChainElementEnumerator enumerator = chain.GetEnumerator();
			enumerator.MoveNext(); // el mismo certificado que el pasado por parametro

			enumerator.MoveNext();

			bool valid = ValidateCertificateByCRL(unsignedProperties, cert, enumerator.Current.Certificate, crlList, digestMethod);

			if (!valid)
			{
				X509Certificate2[] ocspCerts = ValidateCertificateByOCSP(unsignedProperties, cert, enumerator.Current.Certificate, ocspServers, digestMethod, addCertificateOcspUrl);

				if (ocspCerts != null)
				{
					X509Certificate2 startOcspCert = DetermineStartCert(ocspCerts);

					if (!EquivalentDN(startOcspCert.IssuerName, enumerator.Current.Certificate.SubjectName))
					{
						X509Chain chainOcsp = CertificateUtils.GetCertificateChain(startOcspCert, ocspCerts);

						AddCertificate(chainOcsp.ChainElements[1].Certificate, unsignedProperties, true, ocspServers, crlList, digestMethod, addCertificateOcspUrl, ocspCerts);
					}
				}
			}

			AddCertificate(enumerator.Current.Certificate, unsignedProperties, true, ocspServers, crlList, digestMethod, addCertificateOcspUrl, extraCerts);
		}
	}

	private bool ExistsCRL(CRLRefCollection collection, string issuer)
	{
		foreach (CRLRef crlRef in collection)
		{
			if (crlRef.CRLIdentifier.Issuer == issuer)
			{
				return true;
			}
		}

		return false;
	}

	private long? GetCRLNumber(X509Crl crlEntry)
	{
		Asn1OctetString extValue = crlEntry.GetExtensionValue(X509Extensions.CrlNumber);

		if (extValue != null)
		{
			Asn1Object asn1Value = X509ExtensionUtilities.FromExtensionValue(extValue);

			return DerInteger.GetInstance(asn1Value).PositiveValue.LongValue;
		}

		return null;
	}

	private bool ValidateCertificateByCRL(UnsignedProperties unsignedProperties, X509Certificate2 certificate, X509Certificate2 issuer,
		IEnumerable<X509Crl> crlList, DigestMethod digestMethod)
	{
		Org.BouncyCastle.X509.X509Certificate clientCert = certificate.ToBouncyX509Certificate();
		Org.BouncyCastle.X509.X509Certificate issuerCert = issuer.ToBouncyX509Certificate();

		foreach (X509Crl crlEntry in crlList)
		{
			if (crlEntry.IssuerDN.Equivalent(issuerCert.SubjectDN) && crlEntry.NextUpdate.Value > DateTime.Now)
			{
				if (!crlEntry.IsRevoked(clientCert))
				{
					if (!ExistsCRL(unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.CRLRefs.CRLRefCollection,
						issuer.Subject))
					{
						string idCrlValue = "CRLValue-" + Guid.NewGuid().ToString();

						var crlRef = new CRLRef();
						crlRef.CRLIdentifier.UriAttribute = "#" + idCrlValue;
						crlRef.CRLIdentifier.Issuer = issuer.Subject;
						crlRef.CRLIdentifier.IssueTime = crlEntry.ThisUpdate.ToLocalTime();
						crlRef.CRLIdentifier.Number = GetCRLNumber(crlEntry) ?? crlRef.CRLIdentifier.Number;

						byte[] crlEncoded = crlEntry.GetEncoded();
						crlRef.CertDigest.DigestMethod.Algorithm = digestMethod.Uri;
						crlRef.CertDigest.DigestValue = digestMethod.ComputeHash(crlEncoded);

						var crlValue = new CRLValue
						{
							PkiData = crlEncoded,
							Id = idCrlValue
						};

						unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.CRLRefs.CRLRefCollection.Add(crlRef);
						unsignedProperties.UnsignedSignatureProperties.RevocationValues.CRLValues.CRLValueCollection.Add(crlValue);
					}

					return true;
				}
				else
				{
					throw new Exception("The certificate has been revoked.");
				}
			}
		}

		return false;
	}

	private X509Certificate2[] ValidateCertificateByOCSP(UnsignedProperties unsignedProperties, X509Certificate2 client, X509Certificate2 issuer,
		IEnumerable<OcspServer> ocspServers, DigestMethod digestMethod, bool addCertificateOcspUrl)
	{
		bool byKey = false;
		var finalOcspServers = new List<OcspServer>();
		Org.BouncyCastle.X509.X509Certificate clientCert = client.ToBouncyX509Certificate();
		Org.BouncyCastle.X509.X509Certificate issuerCert = issuer.ToBouncyX509Certificate();

		var ocsp = new OcspClient();

		if (addCertificateOcspUrl)
		{
			string certOcspUrl = ocsp.GetAuthorityInformationAccessOcspUrl(issuerCert);

			if (!string.IsNullOrEmpty(certOcspUrl))
			{
				finalOcspServers.Add(new OcspServer(certOcspUrl));
			}
		}

		foreach (OcspServer ocspServer in ocspServers)
		{
			finalOcspServers.Add(ocspServer);
		}

		foreach (OcspServer ocspServer in finalOcspServers)
		{
			byte[] resp = ocsp.QueryBinary(clientCert, issuerCert, ocspServer.Url,
				ocspServer.RequestorName, ocspServer.SigningCertificate);

			Clients.CertificateStatus status = ocsp.ProcessOcspResponse(resp);

			switch (status)
			{
				case Clients.CertificateStatus.Revoked:
					{
						throw new Exception("The certificate has been revoked.");
					}
				case Clients.CertificateStatus.Good:
					{
						var r = new OcspResp(resp);
						byte[] rEncoded = r.GetEncoded();
						var or = (BasicOcspResp)r.GetResponseObject();

						string guidOcsp = Guid.NewGuid().ToString();

						var ocspRef = new OCSPRef();
						ocspRef.OCSPIdentifier.UriAttribute = $"#OcspValue{guidOcsp}";
						ocspRef.CertDigest.DigestMethod.Algorithm = digestMethod.Uri;
						ocspRef.CertDigest.DigestValue = digestMethod.ComputeHash(rEncoded);

						ResponderID rpId = or.ResponderId.ToAsn1Object();
						ocspRef.OCSPIdentifier.ResponderID = GetResponderName(rpId, ref byKey);
						ocspRef.OCSPIdentifier.ByKey = byKey;

						ocspRef.OCSPIdentifier.ProducedAt = or.ProducedAt.ToLocalTime();
						unsignedProperties.UnsignedSignatureProperties.CompleteRevocationRefs.OCSPRefs.OCSPRefCollection.Add(ocspRef);

						var ocspValue = new OCSPValue
						{
							PkiData = rEncoded,
							Id = "OcspValue" + guidOcsp
						};
						unsignedProperties.UnsignedSignatureProperties.RevocationValues.OCSPValues.OCSPValueCollection.Add(ocspValue);

						return or
							.GetCerts()
							.Select(x => new X509Certificate2(x.GetEncoded()))
							.ToArray();
					}
			}
		}

		throw new Exception("The certificate could not be validated.");
	}

	private X509Certificate2 DetermineStartCert(X509Certificate2[] certs)
	{
		X509Certificate2 currentCert = null;
		bool isIssuer = true;

		for (int i = 0; i < certs.Length && isIssuer; i++)
		{
			currentCert = certs[i];
			isIssuer = false;

			for (int j = 0; j < certs.Length; j++)
			{
				if (EquivalentDN(certs[j].IssuerName, currentCert.SubjectName))
				{
					isIssuer = true;
					break;
				}
			}
		}

		return currentCert;
	}

	private void AddTSACertificates(UnsignedProperties unsignedProperties,
		IEnumerable<OcspServer> ocspServers,
		IEnumerable<X509Crl> crlList,
		DigestMethod digestMethod,
		bool addCertificateOcspUrl)
	{
		var token = new TimeStampToken(new CmsSignedData(unsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection[0].EncapsulatedTimeStamp.PkiData));
		IX509Store store = token.GetCertificates("Collection");

		var tsaCerts = new List<X509Certificate2>();
		foreach (object tsaCert in store.GetMatches(null))
		{
			var cert = new X509Certificate2(((Org.BouncyCastle.X509.X509Certificate)tsaCert).GetEncoded());
			tsaCerts.Add(cert);
		}

		X509Certificate2 startCert = DetermineStartCert(tsaCerts.ToArray());
		AddCertificate(startCert, unsignedProperties, true, ocspServers, crlList, digestMethod, addCertificateOcspUrl, tsaCerts.ToArray());
	}

	private void TimeStampCertRefs(SignatureDocument signatureDocument, UpgradeParameters parameters)
	{
		TimeStamp xadesXTimeStamp;
		ArrayList signatureValueElementXpaths;
		byte[] signatureValueHash;

		XmlElement nodoFirma = signatureDocument.XadesSignature.GetSignatureElement();

		var nm = new XmlNamespaceManager(signatureDocument.Document.NameTable);
		nm.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);
		nm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

		XmlNode xmlCompleteCertRefs = nodoFirma.SelectSingleNode("ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs", nm);

		if (xmlCompleteCertRefs == null)
		{
			signatureDocument.UpdateDocument();
		}

		signatureValueElementXpaths = new ArrayList
		{
			"ds:SignatureValue",
			"ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:SignatureTimeStamp",
			"ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteCertificateRefs",
			"ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties/xades:CompleteRevocationRefs",
		};
		signatureValueHash = parameters.DigestMethod.ComputeHash(XmlUtils.ComputeValueOfElementList(signatureDocument.XadesSignature, signatureValueElementXpaths));

		byte[] timestampData = parameters.TimeStampClient
			.GetTimeStampAsync(signatureValueHash, parameters.DigestMethod, true, CancellationToken.None)
			.ConfigureAwait(continueOnCapturedContext: false)
			.GetAwaiter()
			.GetResult();

		xadesXTimeStamp = new TimeStamp("SigAndRefsTimeStamp")
		{
			Id = "SigAndRefsStamp-" + signatureDocument.XadesSignature.Signature.Id
		};
		xadesXTimeStamp.EncapsulatedTimeStamp.PkiData = timestampData;
		xadesXTimeStamp.EncapsulatedTimeStamp.Id = "SigAndRefsStamp-" + Guid.NewGuid().ToString();
		UnsignedProperties unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;

		unsignedProperties.UnsignedSignatureProperties.RefsOnlyTimeStampFlag = false;
		unsignedProperties.UnsignedSignatureProperties.SigAndRefsTimeStampCollection.Add(xadesXTimeStamp);


		signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;
	}
}
