// Transform.cs
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
/// The Transform element contains a single transformation
/// </summary>
public class Transform
{
	/// <summary>
	/// Algorithm of the transformation
	/// </summary>
	public string? Algorithm { get; set; }

	/// <summary>
	/// XPath of the transformation
	/// </summary>
	public string? XPath { get; set; }

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (!string.IsNullOrEmpty(Algorithm))
		{
			result = true;
		}

		if (!string.IsNullOrEmpty(XPath))
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

		Algorithm = xmlElement.HasAttribute("Algorithm")
			? xmlElement.GetAttribute("Algorithm")
			: "";

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("XPath");
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			XPath = xmlNodeList.Item(0)!.InnerText;
		}
		else
		{
			XPath = "";
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement("ds", "Transform", SignedXml.XmlDsigNamespaceUrl);

		if (Algorithm != null)
		{
			result.SetAttribute("Algorithm", Algorithm);
		}
		else
		{
			result.SetAttribute("Algorithm", "");
		}

		if (XPath != null && XPath != "")
		{
			XmlElement bufferXmlElement = creationXmlDocument.CreateElement("ds", "XPath", SignedXml.XmlDsigNamespaceUrl);
			bufferXmlElement.InnerText = XPath;
			result.AppendChild(bufferXmlElement);
		}

		return result;
	}
}
