// RevocationValues.cs
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
	#endregion

	#region Public properties
	/// <summary>
	/// Optional Id for the XML element
	/// </summary>
	public string Id { get; set; }

	/// <summary>
	/// Certificate Revocation Lists
	/// </summary>
	public CRLValues CRLValues { get; set; }

	/// <summary>
	/// Responses from an online certificate status server
	/// </summary>
	public OCSPValues OCSPValues { get; set; }

	/// <summary>
	/// Placeholder for other revocation information is provided for future
	/// use
	/// </summary>
	public OtherValues OtherValues { get; set; }
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public RevocationValues()
	{
		CRLValues = new CRLValues();
		OCSPValues = new OCSPValues();
		OtherValues = new OtherValues();
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
		if (CRLValues != null && CRLValues.HasChanged())
		{
			retVal = true;
		}
		if (OCSPValues != null && OCSPValues.HasChanged())
		{
			retVal = true;
		}
		if (OtherValues != null && OtherValues.HasChanged())
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
			throw new ArgumentNullException(nameof(xmlElement));
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
		xmlNamespaceManager.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xades:CRLValues", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			CRLValues = new CRLValues();
			CRLValues.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		xmlNodeList = xmlElement.SelectNodes("xades:OCSPValues", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			OCSPValues = new OCSPValues();
			OCSPValues.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		xmlNodeList = xmlElement.SelectNodes("xades:OtherValues", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			OtherValues = new OtherValues();
			OtherValues.LoadXml((XmlElement)xmlNodeList.Item(0));
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
		if (Id != null && Id != "")
		{
			retVal.SetAttribute("Id", Id);
		}
		if (CRLValues != null && CRLValues.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(CRLValues.GetXml(), true));
		}
		if (OCSPValues != null && OCSPValues.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(OCSPValues.GetXml(), true));
		}
		if (OtherValues != null && OtherValues.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(OtherValues.GetXml(), true));
		}

		return retVal;
	}
	#endregion
}
