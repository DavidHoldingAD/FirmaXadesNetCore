// SignedProperties.cs
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
/// The SignedProperties element contains a number of properties that are
/// collectively signed by the XMLDSIG signature
/// </summary>
public class SignedProperties
{
	/// <summary>
	/// Default value for the SignedProperties Id attribute
	/// </summary>
	private const string DefaultSignedPropertiesId = "SignedPropertiesId";

	/// <summary>
	/// This Id is used to be able to point the signature reference to this
	/// element.  It is initialized by default.
	/// </summary>
	public string Id { get; set; }

	/// <summary>
	/// The properties that qualify the signature itself or the signer are
	/// included as content of the SignedSignatureProperties element
	/// </summary>
	public SignedSignatureProperties SignedSignatureProperties { get; set; }

	/// <summary>
	/// The SignedDataObjectProperties element contains properties that qualify
	/// some of the signed data objects
	/// </summary>
	public SignedDataObjectProperties SignedDataObjectProperties { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public SignedProperties()
	{
		Id = DefaultSignedPropertiesId; //This is where signature reference points to
		SignedSignatureProperties = new SignedSignatureProperties();
		SignedDataObjectProperties = new SignedDataObjectProperties();
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

		if (SignedSignatureProperties != null && SignedSignatureProperties.HasChanged())
		{
			result = true;
		}

		if (SignedDataObjectProperties != null && SignedDataObjectProperties.HasChanged())
		{
			result = true;
		}

		return result;
	}

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

		Id = xmlElement.HasAttribute("Id")
			? xmlElement.GetAttribute("Id")
			: "";

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:SignedSignatureProperties", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count <= 0)
		{
			throw new CryptographicException("SignedSignatureProperties missing");
		}

		SignedSignatureProperties = new SignedSignatureProperties();
		SignedSignatureProperties.LoadXml((XmlElement)xmlNodeList.Item(0)!);

		xmlNodeList = xmlElement.SelectNodes("xsd:SignedDataObjectProperties", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			SignedDataObjectProperties = new SignedDataObjectProperties();
			SignedDataObjectProperties.LoadXml((XmlElement)xmlNodeList.Item(0)!);
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "SignedProperties", XadesSignedXml.XadesNamespaceUri);

		if (!string.IsNullOrEmpty(Id))
		{
			result.SetAttribute("Id", Id);
		}

		if (SignedSignatureProperties != null)
		{
			result.AppendChild(creationXmlDocument.ImportNode(SignedSignatureProperties.GetXml(), true));
		}
		else
		{
			throw new CryptographicException("SignedSignatureProperties should not be null");
		}

		if (SignedDataObjectProperties != null && SignedDataObjectProperties.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(SignedDataObjectProperties.GetXml(), true));
		}

		return result;
	}
}
