// EncapsulatedPKIData.cs
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
/// EncapsulatedPKIData is used to incorporate a piece of PKI data
/// into an XML structure whereas the PKI data is encoded using an ASN.1
/// encoding mechanism. Examples of such PKI data that are widely used at
/// the time include X509 certificates and revocation lists, OCSP responses,
/// attribute certificates and time-stamps.
/// </summary>
public class EncapsulatedPKIData
{
	/// <summary>
	/// The name of the element when serializing
	/// </summary>
	public string TagName { get; set; }

	/// <summary>
	/// The optional ID attribute can be used to make a reference to an element
	/// of this data type.
	/// </summary>
	public string? Id { get; set; }

	/// <summary>
	/// Base64 encoded content of this data type 
	/// </summary>
	public byte[]? PkiData { get; set; }

	/// <summary>
	/// Constructor with TagName
	/// </summary>
	/// <param name="tagName">Name of the tag when serializing with GetXml</param>
	public EncapsulatedPKIData(string tagName)
	{
		TagName = tagName ?? throw new ArgumentNullException(nameof(tagName));
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

		if (PkiData != null && PkiData.Length > 0)
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

		Id = xmlElement.HasAttribute("Id")
			? xmlElement.GetAttribute("Id")
			: "";

		PkiData = Convert.FromBase64String(xmlElement.InnerText);
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, TagName, XadesSignedXml.XadesNamespaceUri);

		result.SetAttribute("Encoding", "http://uri.etsi.org/01903/v1.2.2#DER");

		if (!string.IsNullOrEmpty(Id))
		{
			result.SetAttribute("Id", Id);
		}

		if (PkiData != null && PkiData.Length > 0)
		{
			result.InnerText = Convert.ToBase64String(PkiData, Base64FormattingOptions.InsertLineBreaks);
		}

		return result;
	}
}
