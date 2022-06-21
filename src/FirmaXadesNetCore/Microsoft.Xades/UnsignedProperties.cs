// UnsignedProperties.cs
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

using System.Xml;

namespace Microsoft.Xades;

/// <summary>
/// The UnsignedProperties element contains a number of properties that are
/// not signed by the XMLDSIG signature
/// </summary>
public class UnsignedProperties
{
	/// <summary>
	/// The optional Id attribute can be used to make a reference to the
	/// UnsignedProperties element
	/// </summary>
	public string? Id { get; set; }

	/// <summary>
	/// UnsignedSignatureProperties may contain properties that qualify XML
	/// signature itself or the signer
	/// </summary>
	public UnsignedSignatureProperties UnsignedSignatureProperties { get; set; }

	/// <summary>
	/// The UnsignedDataObjectProperties element may contain properties that
	/// qualify some of the signed data objects
	/// </summary>
	public UnsignedDataObjectProperties UnsignedDataObjectProperties { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public UnsignedProperties()
	{
		UnsignedSignatureProperties = new UnsignedSignatureProperties();
		UnsignedDataObjectProperties = new UnsignedDataObjectProperties();
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

		if (UnsignedSignatureProperties != null && UnsignedSignatureProperties.HasChanged())
		{
			result = true;
		}

		if (UnsignedDataObjectProperties != null && UnsignedDataObjectProperties.HasChanged())
		{
			result = true;
		}

		return result;
	}

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">XML element containing new state</param>
	/// <param name="counterSignedXmlElement">Element containing parent signature (needed if there are counter signatures)</param>
	public void LoadXml(XmlElement? xmlElement, XmlElement? counterSignedXmlElement)
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

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:UnsignedSignatureProperties", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			UnsignedSignatureProperties = new UnsignedSignatureProperties();
			UnsignedSignatureProperties.LoadXml((XmlElement?)xmlNodeList.Item(0), counterSignedXmlElement);
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:UnsignedDataObjectProperties", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			UnsignedDataObjectProperties = new UnsignedDataObjectProperties();
			UnsignedDataObjectProperties.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "UnsignedProperties", "http://uri.etsi.org/01903/v1.3.2#");
		if (!string.IsNullOrEmpty(Id))
		{
			result.SetAttribute("Id", Id);
		}

		if (UnsignedSignatureProperties != null && UnsignedSignatureProperties.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(UnsignedSignatureProperties.GetXml(), true));
		}
		if (UnsignedDataObjectProperties != null && UnsignedDataObjectProperties.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(UnsignedDataObjectProperties.GetXml(), true));
		}

		return result;
	}
}
