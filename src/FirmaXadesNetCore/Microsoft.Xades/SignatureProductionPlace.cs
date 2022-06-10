// SignatureProductionPlace.cs
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

using System.Xml;

namespace Microsoft.Xades;

/// <summary>
/// In some transactions the purported place where the signer was at the time
/// of signature creation may need to be indicated. In order to provide this
/// information a new property may be included in the signature.
/// This property specifies an address associated with the signer at a
/// particular geographical (e.g. city) location.
/// This is a signed property that qualifies the signer.
/// An XML electronic signature aligned with the present document MAY contain
/// at most one SignatureProductionPlace element.
/// </summary>
public class SignatureProductionPlace
{
	#region Private variables
	private string city;
	private string stateOrProvince;
	private string postalCode;
	private string countryName;
	#endregion

	#region Public properties
	/// <summary>
	/// City where signature was produced
	/// </summary>
	public string City
	{
		get
		{
			return city;
		}
		set
		{
			city = value;
		}
	}

	/// <summary>
	/// State or province where signature was produced
	/// </summary>
	public string StateOrProvince
	{
		get
		{
			return stateOrProvince;
		}
		set
		{
			stateOrProvince = value;
		}
	}

	/// <summary>
	/// Postal code of place where signature was produced
	/// </summary>
	public string PostalCode
	{
		get
		{
			return postalCode;
		}
		set
		{
			postalCode = value;
		}
	}

	/// <summary>
	/// Country where signature was produced
	/// </summary>
	public string CountryName
	{
		get
		{
			return countryName;
		}
		set
		{
			countryName = value;
		}
	}
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public SignatureProductionPlace()
	{
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

		if (!string.IsNullOrEmpty(city))
		{
			retVal = true;
		}

		if (!string.IsNullOrEmpty(stateOrProvince))
		{
			retVal = true;
		}

		if (!string.IsNullOrEmpty(postalCode))
		{
			retVal = true;
		}

		if (!string.IsNullOrEmpty(countryName))
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

		xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xsd:City", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			city = xmlNodeList.Item(0).InnerText;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:PostalCode", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			postalCode = xmlNodeList.Item(0).InnerText;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:StateOrProvince", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			stateOrProvince = xmlNodeList.Item(0).InnerText;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:CountryName", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			countryName = xmlNodeList.Item(0).InnerText;
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
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "SignatureProductionPlace", XadesSignedXml.XadesNamespaceUri);

		if (!string.IsNullOrEmpty(city))
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "City", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = city;
			retVal.AppendChild(bufferXmlElement);
		}

		if (!string.IsNullOrEmpty(stateOrProvince))
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "StateOrProvince", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = stateOrProvince;
			retVal.AppendChild(bufferXmlElement);
		}

		if (!string.IsNullOrEmpty(postalCode))
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "PostalCode", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = postalCode;
			retVal.AppendChild(bufferXmlElement);
		}

		if (countryName != null && countryName != "")
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CountryName", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = countryName;
			retVal.AppendChild(bufferXmlElement);
		}

		return retVal;
	}
	#endregion
}
