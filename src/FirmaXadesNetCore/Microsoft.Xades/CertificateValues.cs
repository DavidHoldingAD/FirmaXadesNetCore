// CertificateValues.cs
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

using System.Collections;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Microsoft.Xades;

/// <summary>
/// The CertificateValues element contains the full set of certificates
/// that have been used to validate	the electronic signature, including the
/// signer's certificate. However, it is not necessary to include one of
/// those certificates into this property, if the certificate is already
/// present in the ds:KeyInfo element of the signature.
/// In fact, both the signer certificate (referenced in the mandatory
/// SigningCertificate property element) and all certificates referenced in
/// the CompleteCertificateRefs property element must be present either in
/// the ds:KeyInfo element of the signature or in the CertificateValues
/// property element.
/// </summary>
public class CertificateValues
{
	#region Private variables
	private string _id;
	private EncapsulatedX509CertificateCollection _encapsulatedX509CertificateCollection;
	private OtherCertificateCollection _otherCertificateCollection;
	#endregion

	#region Public properties

	/// <summary>
	/// Optional Id of the certificate values element
	/// </summary>
	public string Id
	{
		get => _id;
		set => _id = value;
	}

	/// <summary>
	/// A collection of encapsulated X509 certificates
	/// </summary>
	public EncapsulatedX509CertificateCollection EncapsulatedX509CertificateCollection
	{
		get => _encapsulatedX509CertificateCollection;
		set => _encapsulatedX509CertificateCollection = value;
	}

	/// <summary>
	/// Collection of other certificates
	/// </summary>
	public OtherCertificateCollection OtherCertificateCollection
	{
		get => _otherCertificateCollection;
		set => _otherCertificateCollection = value;
	}
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public CertificateValues()
	{
		_encapsulatedX509CertificateCollection = new EncapsulatedX509CertificateCollection();
		_otherCertificateCollection = new OtherCertificateCollection();
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

		if (_id != null && _id != "")
		{
			retVal = true;
		}
		if (_encapsulatedX509CertificateCollection.Count > 0)
		{
			retVal = true;
		}
		if (_otherCertificateCollection.Count > 0)
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
		IEnumerator enumerator;
		XmlElement iterationXmlElement;
		EncapsulatedX509Certificate newEncapsulatedX509Certificate;
		OtherCertificate newOtherCertificate;

		if (xmlElement == null)
		{
			throw new ArgumentNullException("xmlElement");
		}
		if (xmlElement.HasAttribute("Id"))
		{
			_id = xmlElement.GetAttribute("Id");
		}
		else
		{
			_id = "";
		}

		xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);

		_encapsulatedX509CertificateCollection.Clear();
		_otherCertificateCollection.Clear();

		xmlNodeList = xmlElement.SelectNodes("xades:EncapsulatedX509Certificate", xmlNamespaceManager);
		enumerator = xmlNodeList.GetEnumerator();
		try
		{
			while (enumerator.MoveNext())
			{
				iterationXmlElement = enumerator.Current as XmlElement;
				if (iterationXmlElement != null)
				{
					newEncapsulatedX509Certificate = new EncapsulatedX509Certificate();
					newEncapsulatedX509Certificate.LoadXml(iterationXmlElement);
					_encapsulatedX509CertificateCollection.Add(newEncapsulatedX509Certificate);
				}
			}
		}
		finally
		{
			if (enumerator is IDisposable disposable)
			{
				disposable.Dispose();
			}
		}

		xmlNodeList = xmlElement.SelectNodes("xades:OtherCertificate", xmlNamespaceManager);
		enumerator = xmlNodeList.GetEnumerator();
		try
		{
			while (enumerator.MoveNext())
			{
				iterationXmlElement = enumerator.Current as XmlElement;
				if (iterationXmlElement != null)
				{
					newOtherCertificate = new OtherCertificate();
					newOtherCertificate.LoadXml(iterationXmlElement);
					_otherCertificateCollection.Add(newOtherCertificate);
				}
			}
		}
		finally
		{
			if (enumerator is IDisposable disposable)
			{
				disposable.Dispose();
			}
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
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CertificateValues", XadesSignedXml.XadesNamespaceUri);
		retVal.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);

		if (_id != null && _id != "")
		{
			retVal.SetAttribute("Id", _id);
		}

		if (_encapsulatedX509CertificateCollection.Count > 0)
		{
			foreach (EncapsulatedX509Certificate encapsulatedX509Certificate in _encapsulatedX509CertificateCollection)
			{
				if (encapsulatedX509Certificate.HasChanged())
				{
					retVal.AppendChild(creationXmlDocument.ImportNode(encapsulatedX509Certificate.GetXml(), true));
				}
			}
		}
		if (_otherCertificateCollection.Count > 0)
		{
			foreach (OtherCertificate otherCertificate in _otherCertificateCollection)
			{
				if (otherCertificate.HasChanged())
				{
					retVal.AppendChild(creationXmlDocument.ImportNode(otherCertificate.GetXml(), true));
				}
			}
		}

		return retVal;
	}
	#endregion
}
