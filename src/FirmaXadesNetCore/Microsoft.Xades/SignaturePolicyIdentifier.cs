// SignaturePolicyIdentifier.cs
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
/// This class contains an identifier of a signature policy
/// </summary>
public class SignaturePolicyIdentifier
{
	private SignaturePolicyId? _signaturePolicyId;
	private bool _signaturePolicyImplied;

	/// <summary>
	/// The SignaturePolicyId element is an explicit and unambiguous identifier
	/// of a Signature Policy together with a hash value of the signature
	/// policy, so it can be verified that the policy selected by the signer is
	/// the one being used by the verifier. An explicit signature policy has a
	/// globally unique reference, which, in this way, is bound to an
	/// electronic signature by the signer as part of the signature
	/// calculation.
	/// </summary>
	public SignaturePolicyId? SignaturePolicyId
	{
		get => _signaturePolicyId;
		set
		{
			_signaturePolicyId = value;
			_signaturePolicyImplied = false;
		}
	}

	/// <summary>
	/// The empty SignaturePolicyImplied element will appear when the
	/// data object(s) being signed and other external data imply the
	/// signature policy
	/// </summary>
	public bool SignaturePolicyImplied
	{
		get => _signaturePolicyImplied;
		set
		{
			_signaturePolicyImplied = value;
			if (_signaturePolicyImplied == true)
			{
				_signaturePolicyId = null;
			}
		}
	}

	/// <summary>
	/// Default constructor
	/// </summary>
	public SignaturePolicyIdentifier()
	{
		_signaturePolicyId = new SignaturePolicyId();
		_signaturePolicyImplied = false;
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (_signaturePolicyId != null && _signaturePolicyId.HasChanged())
		{
			result = true;
		}

		if (_signaturePolicyImplied)
		{
			result = true;
		}

		return result;
	}

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">XML element containing new state</param>
	public void LoadXml(XmlElement xmlElement)
	{
		if (xmlElement is null)
		{
			throw new ArgumentNullException(nameof(xmlElement));
		}

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:SignaturePolicyId", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			_signaturePolicyId = new SignaturePolicyId();
			_signaturePolicyId.LoadXml((XmlElement?)xmlNodeList.Item(0));
			_signaturePolicyImplied = false;
		}
		else
		{
			xmlNodeList = xmlElement.SelectNodes("xsd:SignaturePolicyImplied", xmlNamespaceManager);
			if (xmlNodeList is not null
				&& xmlNodeList.Count != 0)
			{
				_signaturePolicyImplied = true;
				_signaturePolicyId = null;
			}
			else
			{
				throw new CryptographicException("SignaturePolicyId or SignaturePolicyImplied missing");
			}
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "SignaturePolicyIdentifier", XadesSignedXml.XadesNamespaceUri);

		if (_signaturePolicyImplied)
		{
			//Append empty element as required
			XmlElement bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "SignaturePolicyImplied", XadesSignedXml.XadesNamespaceUri);

			result.AppendChild(bufferXmlElement);
		}
		else
		{
			if (_signaturePolicyId == null || !_signaturePolicyId.HasChanged())
			{
				throw new CryptographicException("SignaturePolicyId or SignaturePolicyImplied missing in SignaturePolicyIdentifier");
			}

			result.AppendChild(creationXmlDocument.ImportNode(_signaturePolicyId.GetXml(), true));
		}

		return result;
	}
}
