// CompleteRevocationRefs.cs
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

using System.Security.Cryptography.Xml;
using System.Xml;

namespace Microsoft.Xades;

/// <summary>
/// This clause defines the XML element containing a full set of
/// references to the revocation data that have been used in the
/// validation of the signer and CA certificates.
/// This is an unsigned property that qualifies the signature.
/// The XML electronic signature aligned with the present document
/// MAY contain at most one CompleteRevocationRefs element.
/// </summary>
public class CompleteRevocationRefs
{
	#region Private variables
	private string id;
	private CRLRefs crlRefs;
	private OCSPRefs ocspRefs;
	private OtherRefs otherRefs;
	#endregion

	#region Public properties
	/// <summary>
	/// The optional Id attribute can be used to make a reference to the CompleteRevocationRefs element
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
	/// Sequences of references to CRLs
	/// </summary>
	public CRLRefs CRLRefs
	{
		get
		{
			return crlRefs;
		}
		set
		{
			crlRefs = value;
		}
	}

	/// <summary>
	/// Sequences of references to OCSP responses
	/// </summary>
	public OCSPRefs OCSPRefs
	{
		get
		{
			return ocspRefs;
		}
		set
		{
			ocspRefs = value;
		}
	}

	/// <summary>
	/// Other references to alternative forms of revocation data
	/// </summary>
	public OtherRefs OtherRefs
	{
		get
		{
			return otherRefs;
		}
		set
		{
			otherRefs = value;
		}
	}
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public CompleteRevocationRefs()
	{
		crlRefs = new CRLRefs();
		ocspRefs = new OCSPRefs();
		otherRefs = new OtherRefs();
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
		if (crlRefs != null && crlRefs.HasChanged())
		{
			retVal = true;
		}
		if (ocspRefs != null && ocspRefs.HasChanged())
		{
			retVal = true;
		}
		if (otherRefs != null && otherRefs.HasChanged())
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
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xsd:CRLRefs", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			crlRefs = new CRLRefs();
			crlRefs.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		xmlNodeList = xmlElement.SelectNodes("xsd:OCSPRefs", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			ocspRefs = new OCSPRefs();
			ocspRefs.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		xmlNodeList = xmlElement.SelectNodes("xsd:OtherRefs", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			otherRefs = new OtherRefs();
			otherRefs.LoadXml((XmlElement)xmlNodeList.Item(0));
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
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CompleteRevocationRefs", XadesSignedXml.XadesNamespaceUri);
		retVal.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);

		if (!string.IsNullOrEmpty(id))
		{
			retVal.SetAttribute("Id", id);
		}
		if (crlRefs != null && crlRefs.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(crlRefs.GetXml(), true));
		}
		if (ocspRefs != null && ocspRefs.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(ocspRefs.GetXml(), true));
		}
		if (otherRefs != null && otherRefs.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(otherRefs.GetXml(), true));
		}

		return retVal;
	}
	#endregion
}

