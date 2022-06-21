// Identifier.cs
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
/// The Identifier element contains a permanent identifier. Once assigned the
/// identifier can never be re-assigned	again. It supports both the mechanism
/// that is used to identify objects in ASN.1 and the mechanism that is
/// usually used to identify objects in an XML environment.
/// </summary>
public class Identifier
{
	/// <summary>
	/// The optional Qualifier attribute can be used to provide a hint about the
	/// applied encoding (values OIDAsURN or OIDAsURI)
	/// </summary>
	public KnownQualifier Qualifier { get; set; }

	/// <summary>
	/// Identification of the XML environment object
	/// </summary>
	public string? IdentifierUri { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public Identifier()
	{
		Qualifier = KnownQualifier.Uninitalized;
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (Qualifier != KnownQualifier.Uninitalized)
		{
			result = true;
		}

		if (!string.IsNullOrEmpty(IdentifierUri))
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

		Qualifier = xmlElement.HasAttribute("Qualifier")
			? (KnownQualifier)Enum.Parse(typeof(KnownQualifier), xmlElement.GetAttribute("Qualifier"), true)
			: KnownQualifier.Uninitalized;

		IdentifierUri = xmlElement.InnerText;
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "Identifier", XadesSignedXml.XadesNamespaceUri);

		if (Qualifier != KnownQualifier.Uninitalized)
		{
			result.SetAttribute("Qualifier", Qualifier.ToString());
		}

		if (!string.IsNullOrWhiteSpace(IdentifierUri))
		{
			result.InnerText = IdentifierUri;
		}

		return result;
	}
}
