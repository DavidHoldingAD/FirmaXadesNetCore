// QualifyingProperties.cs
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
/// The QualifyingProperties element acts as a container element for
/// all the qualifying information that should be added to an XML
/// signature
/// </summary>
public class QualifyingProperties
{
	#region Private variables
	private string id;
	private string target;
	private SignedProperties signedProperties;
	private UnsignedProperties unsignedProperties;
	#endregion

	#region Public properties
	/// <summary>
	/// The optional Id attribute can be used to make a reference to the
	/// QualifyingProperties container.
	/// </summary>
	public string Id
	{
		get
		{
			return id;
		}
		set
		{
			id = value;
		}
	}

	/// <summary>
	/// The mandatory Target attribute refers to the XML signature with which the
	/// qualifying properties are associated.
	/// </summary>
	public string Target
	{
		get
		{
			return target;
		}
		set
		{
			target = value;
		}
	}

	/// <summary>
	/// The SignedProperties element contains a number of properties that are
	/// collectively signed by the XMLDSIG signature
	/// </summary>
	public SignedProperties SignedProperties
	{
		get
		{
			return signedProperties;
		}
		set
		{
			signedProperties = value;
		}
	}

	/// <summary>
	/// The UnsignedProperties element contains a number of properties that are
	/// not signed by the XMLDSIG signature
	/// </summary>
	public UnsignedProperties UnsignedProperties
	{
		get
		{
			return unsignedProperties;
		}
		set
		{
			unsignedProperties = value;
		}
	}
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public QualifyingProperties()
	{
		signedProperties = new SignedProperties();
		unsignedProperties = new UnsignedProperties();
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

		if (!string.IsNullOrEmpty(id))
		{
			retVal = true;
		}

		if (!string.IsNullOrEmpty(target))
		{
			retVal = true;
		}

		if (signedProperties != null && signedProperties.HasChanged())
		{
			retVal = true;
		}

		if (unsignedProperties != null && unsignedProperties.HasChanged())
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
			id = xmlElement.GetAttribute("Id");
		}
		else
		{
			id = "";
		}

		if (xmlElement.HasAttribute("Target"))
		{
			target = xmlElement.GetAttribute("Target");
		}
		else
		{
			target = "";
			throw new CryptographicException("Target attribute missing");
		}

		xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xsd:SignedProperties", xmlNamespaceManager);
		if (xmlNodeList.Count == 0)
		{
			throw new CryptographicException("SignedProperties missing");
		}
		signedProperties = new SignedProperties();
		signedProperties.LoadXml((XmlElement)xmlNodeList.Item(0));

		xmlNodeList = xmlElement.SelectNodes("xsd:UnsignedProperties", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			unsignedProperties = new UnsignedProperties();
			unsignedProperties.LoadXml((XmlElement)xmlNodeList.Item(0), counterSignedXmlElement);
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
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "QualifyingProperties", XadesSignedXml.XadesNamespaceUri);

		if (!string.IsNullOrEmpty(id))
		{
			retVal.SetAttribute("Id", id);
		}

		if (!string.IsNullOrEmpty(target))
		{
			retVal.SetAttribute("Target", target);
		}
		else
		{
			throw new CryptographicException("QualifyingProperties Target attribute has no value");
		}

		if (signedProperties != null && signedProperties.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(signedProperties.GetXml(), true));
		}
		if (unsignedProperties != null && unsignedProperties.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(unsignedProperties.GetXml(), true));
		}

		return retVal;
	}
	#endregion
}
