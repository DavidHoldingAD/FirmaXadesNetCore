﻿// IssuerSerial.cs
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
/// The element IssuerSerial contains the identifier of one of the
/// certificates referenced in the sequence
/// </summary>
public class IssuerSerial
{
	/// <summary>
	/// Name of the X509 certificate issuer
	/// </summary>
	public string? X509IssuerName { get; set; }

	/// <summary>
	/// Serial number of the X509 certificate
	/// </summary>
	public string? X509SerialNumber { get; set; }

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (!string.IsNullOrEmpty(X509IssuerName))
		{
			result = true;
		}

		if (!string.IsNullOrEmpty(X509SerialNumber))
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
		xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("ds:X509IssuerName", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count <= 0)
		{
			throw new CryptographicException("X509IssuerName missing");
		}

		X509IssuerName = xmlNodeList.Item(0)!.InnerText;

		xmlNodeList = xmlElement.SelectNodes("ds:X509SerialNumber", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count <= 0)
		{
			throw new CryptographicException("X509SerialNumber missing");
		}

		X509SerialNumber = xmlNodeList.Item(0)!.InnerText;
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "IssuerSerial", XadesSignedXml.XadesNamespaceUri);

		result.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);

		XmlElement bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlDSigPrefix, "X509IssuerName", SignedXml.XmlDsigNamespaceUrl);
		bufferXmlElement.SetAttribute("xmlns:xades", XadesSignedXml.XadesNamespaceUri);

		if (!string.IsNullOrWhiteSpace(X509IssuerName))
		{
			bufferXmlElement.InnerText = X509IssuerName;
		}

		result.AppendChild(bufferXmlElement);

		bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlDSigPrefix, "X509SerialNumber", SignedXml.XmlDsigNamespaceUrl);
		bufferXmlElement.SetAttribute("xmlns:xades", XadesSignedXml.XadesNamespaceUri);

		if (!string.IsNullOrWhiteSpace(X509SerialNumber))
		{
			bufferXmlElement.InnerText = X509SerialNumber;
		}

		result.AppendChild(bufferXmlElement);

		return result;
	}
}
