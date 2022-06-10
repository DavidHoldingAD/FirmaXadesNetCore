// SignedSignatureProperties.cs
//
// XAdES Starter Kit for Microsoft .NET 3.5 (and above)
// 2010 Microsoft France
//
// Originally published under the CECILL-B Free Software license agreement,
// modified by Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
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
	#region Private variables
	private DateTime signingTime;
	private SigningCertificate signingCertificate;
	private SignaturePolicyIdentifier signaturePolicyIdentifier;
	private SignatureProductionPlace signatureProductionPlace;
	private SignerRole signerRole;
	#endregion

	#region Public properties
	/// <summary>
	/// The signing time property specifies the time at which the signer
	/// performed the signing process. This is a signed property that
	/// qualifies the whole signature. An XML electronic signature aligned
	/// with the present document MUST contain exactly one SigningTime element .
	/// </summary>
	public DateTime SigningTime
	{
		get
		{
			return signingTime;
		}
		set
		{
			signingTime = value;
		}
	}

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
	public SigningCertificate SigningCertificate
	{
		get
		{
			return signingCertificate;
		}
		set
		{
			signingCertificate = value;
		}
	}

	/// <summary>
	/// The signature policy is a set of rules for the creation and
	/// validation of an electronic signature, under which the signature
	/// can be determined to be valid. A given legal/contractual context
	/// may recognize a particular signature policy as meeting its
	/// requirements.
	/// An XML electronic signature aligned with the present document MUST
	/// contain exactly one SignaturePolicyIdentifier element.
	/// </summary>
	public SignaturePolicyIdentifier SignaturePolicyIdentifier
	{
		get
		{
			return signaturePolicyIdentifier;
		}
		set
		{
			signaturePolicyIdentifier = value;
		}
	}

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
	public SignatureProductionPlace SignatureProductionPlace
	{
		get
		{
			return signatureProductionPlace;
		}
		set
		{
			signatureProductionPlace = value;
		}
	}

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
	public SignerRole SignerRole
	{
		get
		{
			return signerRole;
		}
		set
		{
			signerRole = value;
		}
	}
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public SignedSignatureProperties()
	{
		signingTime = DateTime.MinValue;
		signingCertificate = new SigningCertificate();
		signaturePolicyIdentifier = new SignaturePolicyIdentifier();
		signatureProductionPlace = new SignatureProductionPlace();
		signerRole = new SignerRole();
	}
	#endregion

	#region Public methods
	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{ //Should always be serialized
		bool retVal = false;

		retVal = true;

		return retVal;
	}

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">XML element containing new state</param>
	public void LoadXml(XmlElement xmlElement)
	{
		XmlNamespaceManager xmlNamespaceManager;
		XmlNodeList xmlNodeList;

		if (xmlElement == null)
		{
			throw new ArgumentNullException("xmlElement");
		}

		xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xsd:SigningTime", xmlNamespaceManager);
		if (xmlNodeList.Count == 0)
		{
			throw new CryptographicException("SigningTime missing");
		}
		signingTime = XmlConvert.ToDateTime(xmlNodeList.Item(0).InnerText, XmlDateTimeSerializationMode.Local);

		xmlNodeList = xmlElement.SelectNodes("xsd:SigningCertificate", xmlNamespaceManager);
		if (xmlNodeList.Count == 0)
		{
			throw new CryptographicException("SigningCertificate missing");
		}
		signingCertificate = new SigningCertificate();
		signingCertificate.LoadXml((XmlElement)xmlNodeList.Item(0));

		xmlNodeList = xmlElement.SelectNodes("xsd:SignaturePolicyIdentifier", xmlNamespaceManager);
		if (xmlNodeList.Count > 0)
		{
			signaturePolicyIdentifier = new SignaturePolicyIdentifier();
			signaturePolicyIdentifier.LoadXml((XmlElement)xmlNodeList.Item(0));
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:SignatureProductionPlace", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			signatureProductionPlace = new SignatureProductionPlace();
			signatureProductionPlace.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		else
		{
			signatureProductionPlace = null;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:SignerRole", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			signerRole = new SignerRole();
			signerRole.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		else
		{
			signerRole = null;
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		XmlDocument creationXmlDocument;
		XmlElement retVal;
		XmlElement bufferXmlElement;

		creationXmlDocument = new XmlDocument();
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "SignedSignatureProperties", XadesSignedXml.XadesNamespaceUri);

		if (signingTime == DateTime.MinValue)
		{ //SigningTime should be available
			signingTime = DateTime.Now;
		}

		bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "SigningTime", XadesSignedXml.XadesNamespaceUri);

		DateTime truncatedDateTime = signingTime.AddTicks(-(signingTime.Ticks % TimeSpan.TicksPerSecond));

		bufferXmlElement.InnerText = XmlConvert.ToString(truncatedDateTime, XmlDateTimeSerializationMode.Local);

		retVal.AppendChild(bufferXmlElement);

		if (signingCertificate != null && signingCertificate.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(signingCertificate.GetXml(), true));
		}
		else
		{
			throw new CryptographicException("SigningCertificate element missing in SignedSignatureProperties");
		}

		if (signaturePolicyIdentifier != null && signaturePolicyIdentifier.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(signaturePolicyIdentifier.GetXml(), true));
		}

		if (signatureProductionPlace != null && signatureProductionPlace.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(signatureProductionPlace.GetXml(), true));
		}

		if (signerRole != null && signerRole.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(signerRole.GetXml(), true));
		}

		return retVal;
	}
	#endregion
}
