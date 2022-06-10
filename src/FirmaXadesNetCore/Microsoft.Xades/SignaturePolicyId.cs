// SignaturePolicyId.cs
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
	#region Private variables
	private ObjectIdentifier sigPolicyId;
	private Transforms transforms;
	private DigestAlgAndValueType sigPolicyHash;
	private SigPolicyQualifiers sigPolicyQualifiers;
	#endregion

	#region Public properties
	/// <summary>
	/// The SigPolicyId element contains an identifier that uniquely
	/// identifies a specific version of the signature policy
	/// </summary>
	public ObjectIdentifier SigPolicyId
	{
		get
		{
			return sigPolicyId;
		}
		set
		{
			sigPolicyId = value;
		}
	}

	/// <summary>
	/// The optional Transforms element can contain the transformations
	/// performed on the signature policy document before computing its
	/// hash
	/// </summary>
	public Transforms Transforms
	{
		get
		{
			return transforms;
		}
		set
		{
			transforms = value;
		}
	}

	/// <summary>
	/// The SigPolicyHash element contains the identifier of the hash
	/// algorithm and the hash value of the signature policy
	/// </summary>
	public DigestAlgAndValueType SigPolicyHash
	{
		get
		{
			return sigPolicyHash;
		}
		set
		{
			sigPolicyHash = value;
		}
	}

	/// <summary>
	/// The SigPolicyQualifier element can contain additional information
	/// qualifying the signature policy identifier
	/// </summary>
	public SigPolicyQualifiers SigPolicyQualifiers
	{
		get
		{
			return sigPolicyQualifiers;
		}
		set
		{
			sigPolicyQualifiers = value;
		}
	}
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public SignaturePolicyId()
	{
		sigPolicyId = new ObjectIdentifier("SigPolicyId");
		transforms = new Transforms();
		sigPolicyHash = new DigestAlgAndValueType("SigPolicyHash");
		sigPolicyQualifiers = new SigPolicyQualifiers();
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

		if (sigPolicyId != null && sigPolicyId.HasChanged())
		{
			retVal = true;
		}

		if (transforms != null && transforms.HasChanged())
		{
			retVal = true;
		}

		if (sigPolicyHash != null && sigPolicyHash.HasChanged())
		{
			retVal = true;
		}

		if (sigPolicyQualifiers != null && sigPolicyQualifiers.HasChanged())
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
		xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		xmlNodeList = xmlElement.SelectNodes("xsd:SigPolicyId", xmlNamespaceManager);
		if (xmlNodeList.Count == 0)
		{
			throw new CryptographicException("SigPolicyId missing");
		}
		sigPolicyId = new ObjectIdentifier("SigPolicyId");
		sigPolicyId.LoadXml((XmlElement)xmlNodeList.Item(0));

		xmlNodeList = xmlElement.SelectNodes("ds:Transforms", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			transforms = new Transforms();
			transforms.LoadXml((XmlElement)xmlNodeList.Item(0));
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:SigPolicyHash", xmlNamespaceManager);
		if (xmlNodeList.Count == 0)
		{
			throw new CryptographicException("SigPolicyHash missing");
		}
		sigPolicyHash = new DigestAlgAndValueType("SigPolicyHash");
		sigPolicyHash.LoadXml((XmlElement)xmlNodeList.Item(0));

		xmlNodeList = xmlElement.SelectNodes("xsd:SigPolicyQualifiers", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			sigPolicyQualifiers = new SigPolicyQualifiers();
			sigPolicyQualifiers.LoadXml((XmlElement)xmlNodeList.Item(0));
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
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "SignaturePolicyId", XadesSignedXml.XadesNamespaceUri);

		if (sigPolicyId != null && sigPolicyId.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(sigPolicyId.GetXml(), true));
		}

		if (transforms != null && transforms.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(transforms.GetXml(), true));
		}

		if (sigPolicyHash != null && sigPolicyHash.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(sigPolicyHash.GetXml(), true));
		}

		if (sigPolicyQualifiers != null && sigPolicyQualifiers.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(sigPolicyQualifiers.GetXml(), true));
		}

		return retVal;
	}
	#endregion
}
