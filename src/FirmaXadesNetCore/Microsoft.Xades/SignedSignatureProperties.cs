﻿// SignedSignatureProperties.cs
//
// XAdES Starter Kit for Microsoft .NET 3.5 (and above)
// 2010 Microsoft France
//
// Originally published under the CECILL-B Free Software license agreement,
// modified by Dpto. de Nuevas Tecnologнas de la Direcciуn General de Urbanismo del Ayto. de Cartagena
// and published under the GNU Lesser General Public License version 3.
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

using System.Security.Cryptography;
using System.Xml;

namespace Microsoft.Xades;

/// <summary>
/// The properties that qualify the signature itself or the signer are
/// included as content of the SignedSignatureProperties element
/// </summary>
public class SignedSignatureProperties
{
	/// <summary>
	/// The signing time property specifies the time at which the signer
	/// performed the signing process. This is a signed property that
	/// qualifies the whole signature. An XML electronic signature aligned
	/// with the present document MUST contain exactly one SigningTime element .
	/// </summary>
	public DateTime SigningTime { get; set; }

	/// <summary>
	/// The SigningCertificate property is designed to prevent the simple
	/// substitution of the certificate. This property contains references
	/// to certificates and digest values computed on them. The certificate
	/// used to verify the signature shall be identified in the sequence;
	/// the signature policy may mandate other certificates be present,
	/// that may include all the certificates up to the point of trust.
	/// This is a signed property that qualifies the signature. An XML
	/// electronic signature aligned with the present document MUST contain
	/// exactly one SigningCertificate.
	/// </summary>
	public SigningCertificate? SigningCertificate { get; set; }

	/// <summary>
	/// The SigningCertificateV2 property is designed to prevent the simple
	/// substitution of the certificate. This property contains references
	/// to certificates and digest values computed on them. The certificate
	/// used to verify the signature shall be identified in the sequence;
	/// the signature policy may mandate other certificates be present,
	/// that may include all the certificates up to the point of trust.
	/// This is a signed property that qualifies the signature. An XML
	/// electronic signature aligned with the present document MUST contain
	/// exactly one SigningCertificateV2.
	/// </summary>
	public SigningCertificateV2? SigningCertificateV2 { get; set; }

	/// <summary>
	/// The signature policy is a set of rules for the creation and
	/// validation of an electronic signature, under which the signature
	/// can be determined to be valid. A given legal/contractual context
	/// may recognize a particular signature policy as meeting its
	/// requirements.
	/// An XML electronic signature aligned with the present document MUST
	/// contain exactly one SignaturePolicyIdentifier element.
	/// </summary>
	public SignaturePolicyIdentifier? SignaturePolicyIdentifier { get; set; }

	/// <summary>
	/// In some transactions the purported place where the signer was at the time
	/// of signature creation may need to be indicated. In order to provide this
	/// information a new property may be included in the signature.
	/// This property specifies an address associated with the signer at a
	/// particular geographical (e.g. city) location.
	/// This is a signed property that qualifies the signer.
	/// An XML electronic signature aligned with the present document MAY contain
	/// at most one SignatureProductionPlace element.
	/// </summary>
	public SignatureProductionPlace? SignatureProductionPlace { get; set; }

	/// <summary>
	/// According to what has been stated in the Introduction clause, an
	/// electronic signature produced in accordance with the present document
	/// incorporates: "a commitment that has been explicitly endorsed under a
	/// signature policy, at a given time, by a signer under an identifier,
	/// e.g. a name or a pseudonym, and optionally a role".
	/// While the name of the signer is important, the position of the signer
	/// within a company or an organization can be even more important. Some
	/// contracts may only be valid if signed by a user in a particular role,
	/// e.g. a Sales Director. In many cases who the sales Director really is,
	/// is not that important but being sure that the signer is empowered by his
	/// company to be the Sales Director is fundamental.
	/// </summary>
	public SignerRole? SignerRole { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public SignedSignatureProperties()
	{
		SigningTime = DateTime.MinValue;
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
		=> true;

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">XML element containing new state</param>
	public void LoadXml(XmlElement xmlElement)
	{
		if (xmlElement is null)
		{
			throw new ArgumentNullException(nameof(xmlElement));
		}

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:SigningTime", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count <= 0)
		{
			throw new CryptographicException("SigningTime missing");
		}

		SigningTime = XmlConvert.ToDateTime(xmlNodeList.Item(0)!.InnerText, XmlDateTimeSerializationMode.Local);

		xmlNodeList = FindSigningCertificate(xmlElement, xmlNamespaceManager, out bool newVersion);
		if (newVersion)
		{
			SigningCertificateV2 = new SigningCertificateV2();
			SigningCertificateV2.LoadXml((XmlElement)xmlNodeList.Item(0)!);
		}
		else
		{
			SigningCertificate = new SigningCertificate();
			SigningCertificate.LoadXml((XmlElement)xmlNodeList.Item(0)!);
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:SignaturePolicyIdentifier", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count > 0)
		{
			SignaturePolicyIdentifier = new SignaturePolicyIdentifier();
			SignaturePolicyIdentifier.LoadXml((XmlElement)xmlNodeList.Item(0)!);
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:SignatureProductionPlace", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count > 0)
		{
			SignatureProductionPlace = new SignatureProductionPlace();
			SignatureProductionPlace.LoadXml((XmlElement)xmlNodeList.Item(0)!);
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:SignerRole", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count > 0)
		{
			SignerRole = new SignerRole();
			SignerRole.LoadXml((XmlElement)xmlNodeList.Item(0)!);
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument
			.CreateElement(XadesSignedXml.XmlXadesPrefix, "SignedSignatureProperties", XadesSignedXml.XadesNamespaceUri);

		if (SigningTime == DateTime.MinValue)
		{
			//SigningTime should be available
			SigningTime = DateTime.Now;
		}

		XmlElement bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "SigningTime", XadesSignedXml.XadesNamespaceUri);

		DateTime truncatedDateTime = SigningTime.AddTicks(-(SigningTime.Ticks % TimeSpan.TicksPerSecond));

		bufferXmlElement.InnerText = XmlConvert.ToString(truncatedDateTime, XmlDateTimeSerializationMode.Local);

		result.AppendChild(bufferXmlElement);

		if (SigningCertificate != null && SigningCertificate.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(SigningCertificate.GetXml(), true));
		}
		else if (SigningCertificateV2 != null && SigningCertificateV2.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(SigningCertificateV2.GetXml(), true));
		}
		else
		{
			throw new CryptographicException("SigningCertificate element missing in SignedSignatureProperties");
		}

		if (SignaturePolicyIdentifier != null && SignaturePolicyIdentifier.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(SignaturePolicyIdentifier.GetXml(), true));
		}

		if (SignatureProductionPlace != null && SignatureProductionPlace.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(SignatureProductionPlace.GetXml(), true));
		}

		if (SignerRole != null && SignerRole.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(SignerRole.GetXml(), true));
		}

		return result;
	}

	private static XmlNodeList FindSigningCertificate(XmlElement xmlElement,
		XmlNamespaceManager xmlNamespaceManager,
		out bool newVersion)
	{
		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:SigningCertificate", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count > 0)
		{
			newVersion = false;
			return xmlNodeList;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:SigningCertificateV2", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count > 0)
		{
			newVersion = true;
			return xmlNodeList;
		}

		throw new CryptographicException("SigningCertificate or SigningCertificateV2 missing");
	}
}
