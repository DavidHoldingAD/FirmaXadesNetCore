// OCSPIdentifier.cs
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
/// This class includes the name of the server that has produced the
/// referenced response (ResponderID element) and the time indication in
/// the "ProducedAt" field of the referenced response (ProducedAt element).
/// The optional URI attribute could serve to indicate where the OCSP
/// response identified is archived.
/// </summary>
public class OCSPIdentifier
{
	/// <summary>
	/// The optional URI attribute could serve to indicate where the OCSP
	/// response is archived
	/// </summary>
	public string? UriAttribute { get; set; }

	/// <summary>
	/// The ID of the server that has produced the referenced response
	/// </summary>
	public string? ResponderID { get; set; }

	/// <summary>
	/// Time indication in the referenced response
	/// </summary>
	public DateTime ProducedAt { get; set; }

	/// <summary>
	/// Identifier is by key
	/// </summary>
	public bool ByKey { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public OCSPIdentifier()
	{
		ProducedAt = DateTime.MinValue;
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

		if (!string.IsNullOrEmpty(ResponderID))
		{
			result = true;
		}

		if (ProducedAt != DateTime.MinValue)
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

		if (xmlElement.HasAttribute("URI"))
		{
			UriAttribute = xmlElement.GetAttribute("URI");
		}

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xades:ResponderID", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			XmlNode child = xmlNodeList.Item(0)!.ChildNodes.Item(0)!;

			ByKey = child.Name.Contains("ByKey");
			ResponderID = child.InnerText;
		}

		xmlNodeList = xmlElement.SelectNodes("xades:ProducedAt", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			ProducedAt = XmlConvert.ToDateTime(xmlNodeList.Item(0)!.InnerText, XmlDateTimeSerializationMode.Local);
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "OCSPIdentifier", XadesSignedXml.XadesNamespaceUri);

		result.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);

		if (!string.IsNullOrEmpty(UriAttribute))
		{
			result.SetAttribute("URI", UriAttribute);
		}

		if (!string.IsNullOrEmpty(ResponderID))
		{
			XmlElement bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "ResponderID", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);

			XmlElement bufferXmlElement2;
			if (!ByKey && ResponderID.Contains(','))
			{
				bufferXmlElement2 = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "ByName", XadesSignedXml.XadesNamespaceUri);
			}
			else
			{
				bufferXmlElement2 = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "ByKey", XadesSignedXml.XadesNamespaceUri);
			}

			bufferXmlElement2.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);
			bufferXmlElement2.InnerText = ResponderID;

			bufferXmlElement.AppendChild(bufferXmlElement2);

			result.AppendChild(bufferXmlElement);
		}

		if (ProducedAt != DateTime.MinValue)
		{
			XmlElement bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "ProducedAt", XadesSignedXml.XadesNamespaceUri);

			DateTime truncatedDateTime = ProducedAt.AddTicks(-(ProducedAt.Ticks % TimeSpan.TicksPerSecond));

			bufferXmlElement.InnerText = XmlConvert.ToString(truncatedDateTime, XmlDateTimeSerializationMode.Local);

			bufferXmlElement.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);
			result.AppendChild(bufferXmlElement);
		}

		return result;
	}
}
