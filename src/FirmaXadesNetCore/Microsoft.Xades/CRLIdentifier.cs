// CRLIdentifier.cs
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
/// This class includes the issuer (Issuer element), the time when the CRL
/// was issued (IssueTime element) and optionally the number of the CRL
/// (Number element).
/// The Identifier element can be dropped if the CRL could be inferred from
/// other information. Its URI attribute could serve to	indicate where the
/// identified CRL is archived.
/// </summary>
public class CRLIdentifier
{
	#region Private variables
	private long _number;
	#endregion

	#region Public properties
	/// <summary>
	/// The optional URI attribute could serve to indicate where the OCSP
	/// response identified is archived.
	/// </summary>
	public string UriAttribute { get; set; }

	/// <summary>
	/// Issuer of the CRL
	/// </summary>
	public string Issuer { get; set; }

	/// <summary>
	/// Date of issue of the CRL
	/// </summary>
	public DateTime IssueTime { get; set; }

	/// <summary>
	/// Optional number of the CRL
	/// </summary>
	public long Number
	{
		get => _number;
		set => _number = value;
	}
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public CRLIdentifier()
	{
		IssueTime = DateTime.MinValue;
		_number = long.MinValue; //Impossible value
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

		if (!string.IsNullOrEmpty(UriAttribute))
		{
			retVal = true;
		}

		if (!string.IsNullOrEmpty(Issuer))
		{
			retVal = true;
		}

		if (IssueTime != DateTime.MinValue)
		{
			retVal = true;
		}

		if (_number != long.MinValue)
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
		if (xmlElement.HasAttribute("URI"))
		{
			UriAttribute = xmlElement.GetAttribute("URI");
		}

		xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xsd:Issuer", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			Issuer = xmlNodeList.Item(0).InnerText;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:IssueTime", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			IssueTime = XmlConvert.ToDateTime(xmlNodeList.Item(0).InnerText, XmlDateTimeSerializationMode.Local);
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:Number", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			_number = long.Parse(xmlNodeList.Item(0).InnerText);
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
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CRLIdentifier", XadesSignedXml.XadesNamespaceUri);

		retVal.SetAttribute("URI", UriAttribute);

		if (!string.IsNullOrEmpty(Issuer))
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "Issuer", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = Issuer;
			retVal.AppendChild(bufferXmlElement);
		}

		if (IssueTime != DateTime.MinValue)
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "IssueTime", XadesSignedXml.XadesNamespaceUri);

			DateTime truncatedDateTime = IssueTime.AddTicks(-(IssueTime.Ticks % TimeSpan.TicksPerSecond));

			bufferXmlElement.InnerText = XmlConvert.ToString(truncatedDateTime, XmlDateTimeSerializationMode.Local);

			retVal.AppendChild(bufferXmlElement);
		}

		if (_number != long.MinValue)
		{
			bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "Number", XadesSignedXml.XadesNamespaceUri);
			bufferXmlElement.InnerText = _number.ToString();
			retVal.AppendChild(bufferXmlElement);
		}

		return retVal;
	}
	#endregion
}
