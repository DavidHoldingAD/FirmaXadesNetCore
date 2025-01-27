﻿// SPUri.cs
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
/// SPUri represents the URL where the copy of the Signature Policy may be
/// obtained.  The class derives from SigPolicyQualifier.
/// </summary>
public class SPUri : SigPolicyQualifier
{
	/// <summary>
	/// Uri for the sig policy qualifier
	/// </summary>
	public string? Uri { get; set; }

	/// <summary>
	/// Inherited generic element, not used in the SPUri class
	/// </summary>
	public override XmlElement? AnyXmlElement
	{
		get => null; //This does not make sense for SPUri
		set => throw new CryptographicException("Setting AnyXmlElement on a SPUri is not supported");
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public override bool HasChanged()
		=> Uri != null && Uri != "";

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">XML element containing new state</param>
	public override void LoadXml(XmlElement? xmlElement)
	{
		if (xmlElement is null)
		{
			throw new ArgumentNullException(nameof(xmlElement));
		}

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:SPURI", xmlNamespaceManager);
		if (xmlNodeList is null)
		{
			throw new Exception($"Missing required SPURI element.");
		}

		Uri = ((XmlElement)xmlNodeList.Item(0)!).InnerText;
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public override XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement("SigPolicyQualifier", XadesSignedXml.XadesNamespaceUri);

		XmlElement bufferXmlElement = creationXmlDocument.CreateElement("SPURI", XadesSignedXml.XadesNamespaceUri);

		if (!string.IsNullOrWhiteSpace(Uri))
		{
			bufferXmlElement.InnerText = Uri;
		}

		result.AppendChild(creationXmlDocument.ImportNode(bufferXmlElement, true));

		return result;
	}
}
