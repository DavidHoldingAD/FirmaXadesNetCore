// SignaturePolicyId.cs
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
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Microsoft.Xades;

/// <summary>
/// The SignaturePolicyId element is an explicit and unambiguous identifier
/// of a Signature Policy together with a hash value of the signature
/// policy, so it can be verified that the policy selected by the signer is
/// the one being used by the verifier. An explicit signature policy has a
/// globally unique reference, which, in this way, is bound to an
/// electronic signature by the signer as part of the signature
/// calculation.
/// </summary>
public class SignaturePolicyId
{
	/// <summary>
	/// The SigPolicyId element contains an identifier that uniquely
	/// identifies a specific version of the signature policy
	/// </summary>
	public ObjectIdentifier SigPolicyId { get; set; }

	/// <summary>
	/// The optional Transforms element can contain the transformations
	/// performed on the signature policy document before computing its
	/// hash
	/// </summary>
	public Transforms Transforms { get; set; }

	/// <summary>
	/// The SigPolicyHash element contains the identifier of the hash
	/// algorithm and the hash value of the signature policy
	/// </summary>
	public DigestAlgAndValueType SigPolicyHash { get; set; }

	/// <summary>
	/// The SigPolicyQualifier element can contain additional information
	/// qualifying the signature policy identifier
	/// </summary>
	public SigPolicyQualifiers SigPolicyQualifiers { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public SignaturePolicyId()
	{
		SigPolicyId = new ObjectIdentifier("SigPolicyId");
		Transforms = new Transforms();
		SigPolicyHash = new DigestAlgAndValueType("SigPolicyHash");
		SigPolicyQualifiers = new SigPolicyQualifiers();
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (SigPolicyId != null && SigPolicyId.HasChanged())
		{
			result = true;
		}

		if (Transforms != null && Transforms.HasChanged())
		{
			result = true;
		}

		if (SigPolicyHash != null && SigPolicyHash.HasChanged())
		{
			result = true;
		}

		if (SigPolicyQualifiers != null && SigPolicyQualifiers.HasChanged())
		{
			result = true;
		}

		return result;
	}

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">XML element containing new state</param>
	public void LoadXml(XmlElement? xmlElement)
	{
		if (xmlElement is null)
		{
			throw new ArgumentNullException(nameof(xmlElement));
		}

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:SigPolicyId", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count <= 0)
		{
			throw new CryptographicException("SigPolicyId missing");
		}

		SigPolicyId = new ObjectIdentifier("SigPolicyId");
		SigPolicyId.LoadXml((XmlElement?)xmlNodeList.Item(0));

		xmlNodeList = xmlElement.SelectNodes("ds:Transforms", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			Transforms = new Transforms();
			Transforms.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:SigPolicyHash", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count <= 0)
		{
			throw new CryptographicException("SigPolicyHash missing");
		}
		SigPolicyHash = new DigestAlgAndValueType("SigPolicyHash");
		SigPolicyHash.LoadXml((XmlElement?)xmlNodeList.Item(0));

		xmlNodeList = xmlElement.SelectNodes("xsd:SigPolicyQualifiers", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			SigPolicyQualifiers = new SigPolicyQualifiers();
			SigPolicyQualifiers.LoadXml((XmlElement)xmlNodeList.Item(0)!);
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "SignaturePolicyId", XadesSignedXml.XadesNamespaceUri);

		if (SigPolicyId != null && SigPolicyId.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(SigPolicyId.GetXml(), true));
		}

		if (Transforms != null && Transforms.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(Transforms.GetXml(), true));
		}

		if (SigPolicyHash != null && SigPolicyHash.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(SigPolicyHash.GetXml(), true));
		}

		if (SigPolicyQualifiers != null && SigPolicyQualifiers.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(SigPolicyQualifiers.GetXml(), true));
		}

		return result;
	}
}
