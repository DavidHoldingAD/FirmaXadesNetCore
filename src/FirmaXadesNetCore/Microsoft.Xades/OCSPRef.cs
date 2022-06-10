// OCSPRef.cs
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
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Microsoft.Xades;

/// <summary>
/// This class identifies one OCSP response
/// </summary>
public class OCSPRef
{
	#region Private variables
	#endregion

	#region Public properties
	/// <summary>
	/// Identification of one OCSP response
	/// </summary>
	public OCSPIdentifier OCSPIdentifier { get; set; }

	/// <summary>
	/// The digest computed on the DER encoded OCSP response, since it may be
	/// needed to differentiate between two OCSP responses by the same server
	/// with their "ProducedAt" fields within the same second.
	/// </summary>
	public DigestAlgAndValueType CertDigest { get; set; }
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public OCSPRef()
	{
		OCSPIdentifier = new OCSPIdentifier();
		CertDigest = new DigestAlgAndValueType("DigestAlgAndValue");
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

		if (OCSPIdentifier != null && OCSPIdentifier.HasChanged())
		{
			retVal = true;
		}

		if (CertDigest != null && CertDigest.HasChanged())
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

		xmlNodeList = xmlElement.SelectNodes("xsd:OCSPIdentifier", xmlNamespaceManager);
		if (xmlNodeList.Count == 0)
		{
			throw new CryptographicException("OCSPIdentifier missing");
		}
		OCSPIdentifier = new OCSPIdentifier();
		OCSPIdentifier.LoadXml((XmlElement)xmlNodeList.Item(0));

		xmlNodeList = xmlElement.SelectNodes("xsd:DigestAlgAndValue", xmlNamespaceManager);
		if (xmlNodeList.Count == 0)
		{
			CertDigest = null;
		}
		else
		{
			CertDigest = new DigestAlgAndValueType("DigestAlgAndValue");
			CertDigest.LoadXml((XmlElement)xmlNodeList.Item(0));
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
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "OCSPRef", XadesSignedXml.XadesNamespaceUri);
		retVal.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);

		if (OCSPIdentifier != null && OCSPIdentifier.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(OCSPIdentifier.GetXml(), true));
		}
		else
		{
			throw new CryptographicException("OCSPIdentifier element missing in OCSPRef");
		}

		if (CertDigest != null && CertDigest.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(CertDigest.GetXml(), true));
		}

		return retVal;
	}
	#endregion
}
