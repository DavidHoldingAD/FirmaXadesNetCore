// RevocationValues.cs
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
/// The RevocationValues element is used to hold the values of the
/// revocation information which are to be shipped with the XML signature
/// in case of an XML Advanced Electronic Signature with Extended
/// Validation Data (XAdES-X-Long). This is a unsigned property that
/// qualifies the signature. An XML electronic signature aligned with the
/// present document MAY contain at most one RevocationValues element.
/// </summary>
public class RevocationValues
{
	#region Private variables
	private string id;
	private CRLValues crlValues;
	private OCSPValues ocspValues;
	private OtherValues otherValues;
	#endregion

	#region Public properties
	/// <summary>
	/// Optional Id for the XML element
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
	/// Certificate Revocation Lists
	/// </summary>
	public CRLValues CRLValues
	{
		get
		{
			return crlValues;
		}
		set
		{
			crlValues = value;
		}
	}

	/// <summary>
	/// Responses from an online certificate status server
	/// </summary>
	public OCSPValues OCSPValues
	{
		get
		{
			return ocspValues;
		}
		set
		{
			ocspValues = value;
		}
	}

	/// <summary>
	/// Placeholder for other revocation information is provided for future
	/// use
	/// </summary>
	public OtherValues OtherValues
	{
		get
		{
			return otherValues;
		}
		set
		{
			otherValues = value;
		}
	}
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public RevocationValues()
	{
		crlValues = new CRLValues();
		ocspValues = new OCSPValues();
		otherValues = new OtherValues();
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
		if (crlValues != null && crlValues.HasChanged())
		{
			retVal = true;
		}
		if (ocspValues != null && ocspValues.HasChanged())
		{
			retVal = true;
		}
		if (otherValues != null && otherValues.HasChanged())
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
		if (xmlElement.HasAttribute("Id"))
		{
			id = xmlElement.GetAttribute("Id");
		}
		else
		{
			id = "";
		}

		xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xades:CRLValues", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			crlValues = new CRLValues();
			crlValues.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		xmlNodeList = xmlElement.SelectNodes("xades:OCSPValues", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			ocspValues = new OCSPValues();
			ocspValues.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		xmlNodeList = xmlElement.SelectNodes("xades:OtherValues", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			otherValues = new OtherValues();
			otherValues.LoadXml((XmlElement)xmlNodeList.Item(0));
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
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "RevocationValues", XadesSignedXml.XadesNamespaceUri);
		if (id != null && id != "")
		{
			retVal.SetAttribute("Id", id);
		}
		if (crlValues != null && crlValues.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(crlValues.GetXml(), true));
		}
		if (ocspValues != null && ocspValues.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(ocspValues.GetXml(), true));
		}
		if (otherValues != null && otherValues.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(otherValues.GetXml(), true));
		}

		return retVal;
	}
	#endregion
}
