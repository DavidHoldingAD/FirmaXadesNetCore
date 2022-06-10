// UnsignedProperties.cs
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
/// The UnsignedProperties element contains a number of properties that are
/// not signed by the XMLDSIG signature
/// </summary>
public class UnsignedProperties
{
	#region Private variables
	#endregion

	#region Public properties
	/// <summary>
	/// The optional Id attribute can be used to make a reference to the
	/// UnsignedProperties element
	/// </summary>
	public string Id { get; set; }

	/// <summary>
	/// UnsignedSignatureProperties may contain properties that qualify XML
	/// signature itself or the signer
	/// </summary>
	public UnsignedSignatureProperties UnsignedSignatureProperties { get; set; }

	/// <summary>
	/// The UnsignedDataObjectProperties element may contain properties that
	/// qualify some of the signed data objects
	/// </summary>
	public UnsignedDataObjectProperties UnsignedDataObjectProperties { get; set; }
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public UnsignedProperties()
	{
		UnsignedSignatureProperties = new UnsignedSignatureProperties();
		UnsignedDataObjectProperties = new UnsignedDataObjectProperties();
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

		if (!string.IsNullOrEmpty(Id))
		{
			retVal = true;
		}

		if (UnsignedSignatureProperties != null && UnsignedSignatureProperties.HasChanged())
		{
			retVal = true;
		}

		if (UnsignedDataObjectProperties != null && UnsignedDataObjectProperties.HasChanged())
		{
			retVal = true;
		}

		return retVal;
	}

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">XML element containing new state</param>
	/// <param name="counterSignedXmlElement">Element containing parent signature (needed if there are counter signatures)</param>
	public void LoadXml(XmlElement xmlElement, XmlElement counterSignedXmlElement)
	{
		XmlNamespaceManager xmlNamespaceManager;
		XmlNodeList xmlNodeList;

		if (xmlElement == null)
		{
			throw new ArgumentNullException("xmlElement");
		}
		if (xmlElement.HasAttribute("Id"))
		{
			Id = xmlElement.GetAttribute("Id");
		}
		else
		{
			Id = "";
		}

		xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xsd:UnsignedSignatureProperties", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			UnsignedSignatureProperties = new UnsignedSignatureProperties();
			UnsignedSignatureProperties.LoadXml((XmlElement)xmlNodeList.Item(0), counterSignedXmlElement);
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:UnsignedDataObjectProperties", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			UnsignedDataObjectProperties = new UnsignedDataObjectProperties();
			UnsignedDataObjectProperties.LoadXml((XmlElement)xmlNodeList.Item(0));
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

		creationXmlDocument = new XmlDocument();
		//retVal = creationXmlDocument.CreateElement("UnsignedProperties", XadesSignedXml.XadesNamespaceUri);
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "UnsignedProperties", "http://uri.etsi.org/01903/v1.3.2#");
		if (!string.IsNullOrEmpty(Id))
		{
			retVal.SetAttribute("Id", Id);
		}

		if (UnsignedSignatureProperties != null && UnsignedSignatureProperties.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(UnsignedSignatureProperties.GetXml(), true));
		}
		if (UnsignedDataObjectProperties != null && UnsignedDataObjectProperties.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(UnsignedDataObjectProperties.GetXml(), true));
		}

		return retVal;
	}
	#endregion
}
