// CompleteCertificateRefs.cs
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
/// This clause defines the XML element containing the sequence of
/// references to the full set of CA certificates that have been used
/// to validate the electronic signature up to (but not including) the
/// signer's certificate. This is an unsigned property that qualifies
/// the signature.
/// An XML electronic signature aligned with the XAdES standard may
/// contain at most one CompleteCertificateRefs element.
/// </summary>
public class CompleteCertificateRefs
{
	/// <summary>
	/// The optional Id attribute can be used to make a reference to the CompleteCertificateRefs element
	/// </summary>
	public string? Id { get; set; }

	/// <summary>
	/// The CertRefs element contains a sequence of Cert elements, incorporating the
	/// digest of each certificate and optionally the issuer and serial number identifier.
	/// </summary>
	public CertRefs CertRefs { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public CompleteCertificateRefs()
	{
		CertRefs = new CertRefs();
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
		if (CertRefs != null && CertRefs.HasChanged())
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

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:CertRefs", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			CertRefs = new CertRefs();
			CertRefs.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CompleteCertificateRefs", XadesSignedXml.XadesNamespaceUri);

		result.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);

		if (!string.IsNullOrEmpty(Id))
		{
			result.SetAttribute("Id", Id);
		}

		if (CertRefs != null && CertRefs.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(CertRefs.GetXml(), true));
		}

		return result;
	}
}
