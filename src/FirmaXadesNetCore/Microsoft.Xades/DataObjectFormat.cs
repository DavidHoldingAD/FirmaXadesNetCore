// DataObjectFormat.cs
//
// XAdES Starter Kit for Microsoft .NET 3.5 (and above)
// 2010 Microsoft France
//
// Originally published under the CECILL-B Free Software license agreement,
// modified by Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
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
	private string objectReferenceAttribute;
	private string description;
	private ObjectIdentifier objectIdentifier;
	private string mimeType;
	private string encoding;
	#endregion

	#region Public properties
	/// <summary>
	/// The mandatory ObjectReference attribute refers to the Reference element
	/// of the signature corresponding with the data object qualified by this
	/// property.
	/// </summary>
	public string ObjectReferenceAttribute
	{
		get
		{
			return objectReferenceAttribute;
		}
		set
		{
			objectReferenceAttribute = value;
		}
	}

	/// <summary>
	/// Textual information related to the signed data object
	/// </summary>
	public string Description
	{
		get
		{
			return description;
		}
		set
		{
			description = value;
		}
	}

	/// <summary>
	/// An identifier indicating the type of the signed data object
	/// </summary>
	public ObjectIdentifier ObjectIdentifier
	{
		get
		{
			return objectIdentifier;
		}
		set
		{
			objectIdentifier = value;
		}
	}

	/// <summary>
	/// An indication of the MIME type of the signed data object
	/// </summary>
	public string MimeType
	{
		get
		{
			return mimeType;
		}
		set
		{
			mimeType = value;
		}
	}

	/// <summary>
	/// An indication of the encoding format of the signed data object
	/// </summary>
	public string Encoding
	{
		get
		{
			return encoding;
		}
		set
		{
			encoding = value;
		}
	}
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public DataObjectFormat()
	{
		objectIdentifier = new ObjectIdentifier("ObjectIdentifier");
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

		if (!string.IsNullOrEmpty(objectReferenceAttribute))
		{
			retVal = true;
		}

		if (!string.IsNullOrEmpty(description))
		{
			retVal = true;
		}

		if (objectIdentifier != null && objectIdentifier.HasChanged())
		{
			retVal = true;
		}

		if (!string.IsNullOrEmpty(mimeType))
		{
			retVal = true;
		}

		if (!string.IsNullOrEmpty(encoding))
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
			objectReferenceAttribute = xmlElement.GetAttribute("ObjectReference");
		}
		else
		{
			objectReferenceAttribute = "";
			throw new CryptographicException("ObjectReference attribute missing");
		}

		xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xsd:Description", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			description = xmlNodeList.Item(0).InnerText;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:ObjectIdentifier", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			objectIdentifier = new ObjectIdentifier("ObjectIdentifier");
			objectIdentifier.LoadXml((XmlElement)xmlNodeList.Item(0));
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:MimeType", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			mimeType = xmlNodeList.Item(0).InnerText;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:Encoding", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			encoding = xmlNodeList.Item(0).InnerText;
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

		if ((objectReferenceAttribute != null) && ((objectReferenceAttribute != "")))
		{
			retVal.SetAttribute("ObjectReference", objectReferenceAttribute);
		}
		else
		{
			throw new CryptographicException("Attribute ObjectReference missing");
		}

		if (!string.IsNullOrEmpty(description))
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "Description", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = description;
			retVal.AppendChild(bufferXmlElement);
		}

		if (objectIdentifier != null && objectIdentifier.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(objectIdentifier.GetXml(), true));
		}

		if (!string.IsNullOrEmpty(mimeType))
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "MimeType", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = mimeType;
			retVal.AppendChild(bufferXmlElement);
		}

		if (!string.IsNullOrEmpty(encoding))
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "Encoding", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = encoding;
			retVal.AppendChild(bufferXmlElement);
		}

		return retVal;
	}
	#endregion
}
