// CRLRef.cs
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
/// This class contains information about a Certificate Revocation List (CRL)
/// </summary>
public class CRLRef
{
	#region Private variables
	#endregion

	#region Public properties
	/// <summary>
	/// The digest of the entire DER encoded
	/// </summary>
	public DigestAlgAndValueType CertDigest { get; set; }

	/// <summary>
	/// CRLIdentifier is a set of data including the issuer, the time when
	/// the CRL was issued and optionally the number of the CRL.
	/// The Identifier element can be dropped if the CRL could be inferred
	/// from other information.
	/// </summary>
	public CRLIdentifier CRLIdentifier { get; set; }
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public CRLRef()
	{
		CertDigest = new DigestAlgAndValueType("DigestAlgAndValue");
		CRLIdentifier = new CRLIdentifier();
	}
	#endregion

	#region Public methods
	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool retVal = false;

		if (CertDigest != null && CertDigest.HasChanged())
		{
			retVal = true;
		}

		if (CRLIdentifier != null && CRLIdentifier.HasChanged())
		{
			retVal = true;
		}

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
			throw new ArgumentNullException(nameof(xmlElement));
		}

		xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xsd:DigestAlgAndValue", xmlNamespaceManager);
		if (xmlNodeList.Count == 0)
		{
			throw new CryptographicException("DigestAlgAndValue missing");
		}
		CertDigest = new DigestAlgAndValueType("DigestAlgAndValue");
		CertDigest.LoadXml((XmlElement)xmlNodeList.Item(0));

		xmlNodeList = xmlElement.SelectNodes("xsd:CRLIdentifier", xmlNamespaceManager);
		if (xmlNodeList.Count == 0)
		{
			CRLIdentifier = null;
		}
		else
		{
			CRLIdentifier = new CRLIdentifier();
			CRLIdentifier.LoadXml((XmlElement)xmlNodeList.Item(0));
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

		creationXmlDocument = new XmlDocument();
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CRLRef", XadesSignedXml.XadesNamespaceUri);

		if (CertDigest != null && CertDigest.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(CertDigest.GetXml(), true));
		}
		else
		{
			throw new CryptographicException("DigestAlgAndValue element missing in CRLRef");
		}

		if (CRLIdentifier != null && CRLIdentifier.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(CRLIdentifier.GetXml(), true));
		}

		return retVal;
	}
	#endregion
}
