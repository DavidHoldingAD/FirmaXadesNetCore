// HashDataInfo.cs
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
/// The HashDataInfo class contains a uri attribute referencing a data object
/// and a ds:Transforms element indicating the transformations to make to this
/// data object.
/// The sequence of HashDataInfo elements will be used to produce the input of
/// the hash computation process whose result will be included in the
/// timestamp request to be sent to the TSA.
/// </summary>
public class HashDataInfo
{
	/// <summary>
	/// Uri referencing a data object
	/// </summary>
	public string? UriAttribute { get; set; }

	/// <summary>
	/// Transformations to make to this data object
	/// </summary>
	public Transforms Transforms { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public HashDataInfo()
	{
		Transforms = new Transforms();
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (!string.IsNullOrEmpty(UriAttribute))
		{
			result = true;
		}

		if (Transforms != null && Transforms.HasChanged())
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

		if (!xmlElement.HasAttribute("Uri"))
		{
			throw new CryptographicException("uri attribute missing");
		}

		UriAttribute = xmlElement.GetAttribute("uri");

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:Transforms", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			Transforms = new Transforms();
			Transforms.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement("HashDataInfo", XadesSignedXml.XadesNamespaceUri);

		result.SetAttribute("uri", UriAttribute);

		if (Transforms != null && Transforms.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(Transforms.GetXml(), true));
		}

		return result;
	}
}
