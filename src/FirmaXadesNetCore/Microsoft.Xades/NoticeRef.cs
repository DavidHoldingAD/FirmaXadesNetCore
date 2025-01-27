﻿// NoticeRef.cs
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
/// The NoticeRef element names an organization and identifies by
/// numbers a group of textual statements prepared by that organization,
/// so that the application could get the explicit notices from a notices file.
/// </summary>
public class NoticeRef
{
	/// <summary>
	/// Organization issuing the signature policy
	/// </summary>
	public string? Organization { get; set; }

	/// <summary>
	/// Numerical identification of textual statements prepared by the organization,
	/// so that the application can get the explicit notices from a notices file.
	/// </summary>
	public NoticeNumbers NoticeNumbers { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public NoticeRef()
	{
		NoticeNumbers = new NoticeNumbers();
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (!string.IsNullOrEmpty(Organization))
		{
			result = true;
		}

		if (NoticeNumbers != null && NoticeNumbers.HasChanged())
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

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:Organization", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count <= 0)
		{
			throw new CryptographicException("Organization missing");
		}

		Organization = xmlNodeList.Item(0)!.InnerText;

		xmlNodeList = xmlElement.SelectNodes("xsd:NoticeNumbers", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count < 0)
		{
			throw new CryptographicException("NoticeNumbers missing");
		}

		NoticeNumbers = new NoticeNumbers();
		NoticeNumbers.LoadXml((XmlElement)xmlNodeList.Item(0)!);
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement("NoticeRef", XadesSignedXml.XadesNamespaceUri);

		if (Organization == null)
		{
			throw new CryptographicException("Organization can't be null");
		}

		XmlElement bufferXmlElement = creationXmlDocument.CreateElement("Organization", XadesSignedXml.XadesNamespaceUri);
		bufferXmlElement.InnerText = Organization;
		result.AppendChild(bufferXmlElement);

		if (NoticeNumbers == null)
		{
			throw new CryptographicException("NoticeNumbers can't be null");
		}

		result.AppendChild(creationXmlDocument.ImportNode(NoticeNumbers.GetXml(), true));

		return result;
	}
}
