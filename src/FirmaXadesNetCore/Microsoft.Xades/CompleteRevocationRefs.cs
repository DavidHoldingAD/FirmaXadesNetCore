// CompleteRevocationRefs.cs
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

using System.Security.Cryptography.Xml;
using System.Xml;

namespace Microsoft.Xades;

/// <summary>
/// This clause defines the XML element containing a full set of
/// references to the revocation data that have been used in the
/// validation of the signer and CA certificates.
/// This is an unsigned property that qualifies the signature.
/// The XML electronic signature aligned with the present document
/// MAY contain at most one CompleteRevocationRefs element.
/// </summary>
public class CompleteRevocationRefs
{
	/// <summary>
	/// The optional Id attribute can be used to make a reference to the CompleteRevocationRefs element
	/// </summary>
	public string? Id { get; set; }

	/// <summary>
	/// Sequences of references to CRLs
	/// </summary>
	public CRLRefs CRLRefs { get; set; }

	/// <summary>
	/// Sequences of references to OCSP responses
	/// </summary>
	public OCSPRefs OCSPRefs { get; set; }

	/// <summary>
	/// Other references to alternative forms of revocation data
	/// </summary>
	public OtherRefs OtherRefs { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public CompleteRevocationRefs()
	{
		CRLRefs = new CRLRefs();
		OCSPRefs = new OCSPRefs();
		OtherRefs = new OtherRefs();
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (!string.IsNullOrEmpty(Id))
		{
			result = true;
		}

		if (CRLRefs != null && CRLRefs.HasChanged())
		{
			result = true;
		}

		if (OCSPRefs != null && OCSPRefs.HasChanged())
		{
			result = true;
		}

		if (OtherRefs != null && OtherRefs.HasChanged())
		{
			result = true;
		}

		return result;
	}

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">XML element containing new state</param>
	public void LoadXml(XmlElement? xmlElement)
	{
		if (xmlElement is null)
		{
			throw new ArgumentNullException(nameof(xmlElement));
		}

		Id = xmlElement.HasAttribute("Id")
			? xmlElement.GetAttribute("Id")
			: "";

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:CRLRefs", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			CRLRefs = new CRLRefs();
			CRLRefs.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:OCSPRefs", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			OCSPRefs = new OCSPRefs();
			OCSPRefs.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:OtherRefs", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			OtherRefs = new OtherRefs();
			OtherRefs.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CompleteRevocationRefs", XadesSignedXml.XadesNamespaceUri);

		result.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);

		if (!string.IsNullOrEmpty(Id))
		{
			result.SetAttribute("Id", Id);
		}

		if (CRLRefs != null && CRLRefs.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(CRLRefs.GetXml(), true));
		}

		if (OCSPRefs != null && OCSPRefs.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(OCSPRefs.GetXml(), true));
		}

		if (OtherRefs != null && OtherRefs.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(OtherRefs.GetXml(), true));
		}

		return result;
	}
}
