// DataObjectFormat.cs
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
/// The DataObjectFormat element provides information that describes the
/// format of the signed data object. This element must be present when it
/// is mandatory to present the signed data object to human users on
/// verification.
/// This is a signed property that qualifies one specific signed data
/// object. In consequence, a XAdES signature may contain more than one
/// DataObjectFormat elements, each one qualifying one signed data object.
/// </summary>
public class DataObjectFormat
{
	#region Private variables
	private string _encoding;
	#endregion

	#region Public properties
	/// <summary>
	/// The mandatory ObjectReference attribute refers to the Reference element
	/// of the signature corresponding with the data object qualified by this
	/// property.
	/// </summary>
	public string ObjectReferenceAttribute { get; set; }

	/// <summary>
	/// Textual information related to the signed data object
	/// </summary>
	public string Description { get; set; }

	/// <summary>
	/// An identifier indicating the type of the signed data object
	/// </summary>
	public ObjectIdentifier ObjectIdentifier { get; set; }

	/// <summary>
	/// An indication of the MIME type of the signed data object
	/// </summary>
	public string MimeType { get; set; }

	/// <summary>
	/// An indication of the encoding format of the signed data object
	/// </summary>
	public string Encoding
	{
		get => _encoding;
		set => _encoding = value;
	}
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public DataObjectFormat()
	{
		ObjectIdentifier = new ObjectIdentifier("ObjectIdentifier");
	}
	#endregion

	#region Public methods
	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool retVal = false;

		if (!string.IsNullOrEmpty(ObjectReferenceAttribute))
		{
			retVal = true;
		}

		if (!string.IsNullOrEmpty(Description))
		{
			retVal = true;
		}

		if (ObjectIdentifier != null && ObjectIdentifier.HasChanged())
		{
			retVal = true;
		}

		if (!string.IsNullOrEmpty(MimeType))
		{
			retVal = true;
		}

		if (!string.IsNullOrEmpty(_encoding))
		{
			retVal = true;
		}

		return retVal;
	}

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">XML element containing new state</param>
	public void LoadXml(XmlElement xmlElement)
	{
		XmlNamespaceManager xmlNamespaceManager;
		XmlNodeList xmlNodeList;

		if (xmlElement == null)
		{
			throw new ArgumentNullException("xmlElement");
		}

		if (xmlElement.HasAttribute("ObjectReference"))
		{
			ObjectReferenceAttribute = xmlElement.GetAttribute("ObjectReference");
		}
		else
		{
			ObjectReferenceAttribute = "";
			throw new CryptographicException("ObjectReference attribute missing");
		}

		xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xsd:Description", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			Description = xmlNodeList.Item(0).InnerText;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:ObjectIdentifier", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			ObjectIdentifier = new ObjectIdentifier("ObjectIdentifier");
			ObjectIdentifier.LoadXml((XmlElement)xmlNodeList.Item(0));
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:MimeType", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			MimeType = xmlNodeList.Item(0).InnerText;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:Encoding", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			_encoding = xmlNodeList.Item(0).InnerText;
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		XmlDocument creationXmlDocument;
		XmlElement retVal;
		XmlElement bufferXmlElement;

		creationXmlDocument = new XmlDocument();
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "DataObjectFormat", XadesSignedXml.XadesNamespaceUri);

		if ((ObjectReferenceAttribute != null) && ((ObjectReferenceAttribute != "")))
		{
			retVal.SetAttribute("ObjectReference", ObjectReferenceAttribute);
		}
		else
		{
			throw new CryptographicException("Attribute ObjectReference missing");
		}

		if (!string.IsNullOrEmpty(Description))
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "Description", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = Description;
			retVal.AppendChild(bufferXmlElement);
		}

		if (ObjectIdentifier != null && ObjectIdentifier.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(ObjectIdentifier.GetXml(), true));
		}

		if (!string.IsNullOrEmpty(MimeType))
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "MimeType", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = MimeType;
			retVal.AppendChild(bufferXmlElement);
		}

		if (!string.IsNullOrEmpty(_encoding))
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "Encoding", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = _encoding;
			retVal.AppendChild(bufferXmlElement);
		}

		return retVal;
	}
	#endregion
}
