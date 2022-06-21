// DigestAlgAndValueType.cs
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
/// This class indicates the algortithm used to calculate the digest and
/// the digest value itself
/// </summary>
public class DigestAlgAndValueType
{
	/// <summary>
	/// The name of the element when serializing
	/// </summary>
	public string TagName { get; }

	/// <summary>
	/// Indicates the digest algorithm
	/// </summary>
	public DigestMethod DigestMethod { get; set; }

	/// <summary>
	/// Contains the value of the digest
	/// </summary>
	public byte[]? DigestValue { get; set; }

	/// <summary>
	/// Constructor with TagName
	/// </summary>
	/// <param name="tagName">Name of the tag when serializing with GetXml</param>
	public DigestAlgAndValueType(string tagName)
	{
		TagName = tagName ?? throw new ArgumentNullException(nameof(tagName));
		DigestMethod = new DigestMethod();
		DigestValue = null;
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (DigestMethod != null && DigestMethod.HasChanged())
		{
			result = true;
		}

		if (DigestValue != null && DigestValue.Length > 0)
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
		xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("ds:DigestMethod", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count <= 0)
		{
			throw new CryptographicException("DigestMethod missing");
		}

		DigestMethod = new DigestMethod();
		DigestMethod.LoadXml((XmlElement)xmlNodeList.Item(0)!);

		xmlNodeList = xmlElement.SelectNodes("ds:DigestValue", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count <= 0)
		{
			throw new CryptographicException("DigestValue missing");
		}
		DigestValue = Convert.FromBase64String(xmlNodeList.Item(0)!.InnerText);
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, TagName, XadesSignedXml.XadesNamespaceUri);

		result.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);

		if (DigestMethod == null || !DigestMethod.HasChanged())
		{
			throw new CryptographicException("DigestMethod element missing in DigestAlgAndValueType");
		}

		result.AppendChild(creationXmlDocument.ImportNode(DigestMethod.GetXml(), true));

		if (DigestValue == null || DigestValue.Length == 0)
		{
			throw new CryptographicException("DigestValue element missing in DigestAlgAndValueType");
		}

		XmlElement bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlDSigPrefix, "DigestValue", SignedXml.XmlDsigNamespaceUrl);
		bufferXmlElement.SetAttribute("xmlns:xades", XadesSignedXml.XadesNamespaceUri);

		bufferXmlElement.InnerText = Convert.ToBase64String(DigestValue);
		result.AppendChild(bufferXmlElement);

		return result;
	}
}
