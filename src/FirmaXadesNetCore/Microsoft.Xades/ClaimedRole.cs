﻿// ClaimedRole.cs
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
/// This class contains a roles claimed by the signer but not it is not a
/// certified role
/// </summary>
public class ClaimedRole
{
	/// <summary>
	/// The generic XML element that represents a claimed role
	/// </summary>
	public XmlElement? AnyXmlElement { get; set; }

	/// <summary>
	/// Gets or sets the inner text.
	/// </summary>
	public string? InnerText { get; set; }

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (AnyXmlElement != null)
		{
			result = true;
		}

		if (!string.IsNullOrEmpty(InnerText))
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
		AnyXmlElement = xmlElement ?? throw new ArgumentNullException(nameof(xmlElement));
		InnerText = xmlElement.InnerText;
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "ClaimedRole", XadesSignedXml.XadesNamespaceUri);

		if (!string.IsNullOrEmpty(InnerText))
		{
			result.InnerText = InnerText;
		}

		if (AnyXmlElement != null)
		{
			result.AppendChild(creationXmlDocument.ImportNode(AnyXmlElement, true));
		}

		return result;
	}
}
