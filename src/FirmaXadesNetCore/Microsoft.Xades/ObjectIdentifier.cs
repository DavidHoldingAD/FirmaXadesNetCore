// ObjectIdentifier.cs
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
/// ObjectIdentifier allows the specification of an unique and permanent
/// object of an object and some additional information about the nature of
/// the	data object
/// </summary>
public class ObjectIdentifier
{
	/// <summary>
	/// The name of the element when serializing
	/// </summary>
	public string TagName { get; }

	/// <summary>
	/// Specification of an unique and permanent identifier
	/// </summary>
	public Identifier Identifier { get; set; }

	/// <summary>
	/// Textual description of the nature of the data object
	/// </summary>
	public string? Description { get; set; }

	/// <summary>
	/// References to documents where additional information about the
	/// nature of the data object can be found
	/// </summary>
	public DocumentationReferences DocumentationReferences { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public ObjectIdentifier()
	{
		TagName = "ObjectIdentifier";
		Identifier = new Identifier();
		DocumentationReferences = new DocumentationReferences();
	}

	/// <summary>
	/// Constructor with TagName
	/// </summary>
	/// <param name="tagName">Name of the tag when serializing with GetXml</param>
	public ObjectIdentifier(string tagName)
		: this()
	{
		TagName = tagName;
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (Identifier != null && Identifier.HasChanged())
		{
			result = true;
		}

		if (!string.IsNullOrEmpty(Description))
		{
			result = true;
		}

		if (DocumentationReferences != null && DocumentationReferences.HasChanged())
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

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:Identifier", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count <= 0)
		{
			throw new CryptographicException("Identifier missing");
		}

		Identifier = new Identifier();
		Identifier.LoadXml((XmlElement?)xmlNodeList.Item(0));

		xmlNodeList = xmlElement.SelectNodes("xsd:Description", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			Description = xmlNodeList.Item(0)!.InnerText;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:DocumentationReferences", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			DocumentationReferences = new DocumentationReferences();
			DocumentationReferences.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, TagName, XadesSignedXml.XadesNamespaceUri);

		if (Identifier != null && Identifier.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(Identifier.GetXml(), true));
		}
		else
		{
			throw new CryptographicException("Identifier element missing in OjectIdentifier");
		}

		XmlElement bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "Description", XadesSignedXml.XadesNamespaceUri);

		if (!string.IsNullOrWhiteSpace(Description))
		{
			bufferXmlElement.InnerText = Description;
		}

		result.AppendChild(bufferXmlElement);

		if (DocumentationReferences != null && DocumentationReferences.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(DocumentationReferences.GetXml(), true));
		}

		return result;
	}
}
