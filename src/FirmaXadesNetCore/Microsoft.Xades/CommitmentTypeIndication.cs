﻿// CommitmentTypeIndication.cs
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
using System.Security.Cryptography;
using System.Xml;

namespace Microsoft.Xades;

/// <summary>
/// The commitment type can be indicated in the electronic signature
/// by either explicitly using a commitment type indication in the
/// electronic signature or implicitly or explicitly from the semantics
/// of the signed data object.
/// If the indicated commitment type is explicit by means of a commitment
/// type indication in the electronic signature, acceptance of a verified
/// signature implies acceptance of the semantics of that commitment type.
/// The semantics of explicit commitment types indications shall be
/// specified either as part of the signature policy or may be registered
/// for	generic use across multiple policies.
/// </summary>
public class CommitmentTypeIndication
{
	private ObjectReferenceCollection _objectReferenceCollection;
	private bool _allSignedDataObjects;

	/// <summary>
	/// The CommitmentTypeId element univocally identifies the type of commitment made by the signer.
	/// A number of commitments have been already identified and assigned corresponding OIDs.
	/// </summary>
	public ObjectIdentifier CommitmentTypeId { get; set; }

	/// <summary>
	/// Collection of object references
	/// </summary>
	public ObjectReferenceCollection ObjectReferenceCollection
	{
		get => _objectReferenceCollection;
		set
		{
			_objectReferenceCollection = value;
			if (_objectReferenceCollection != null)
			{
				if (_objectReferenceCollection.Count > 0)
				{
					_allSignedDataObjects = false;
				}
			}
		}
	}

	/// <summary>
	/// If all the signed data objects share the same commitment, the
	/// AllSignedDataObjects empty element MUST be present.
	/// </summary>
	public bool AllSignedDataObjects
	{
		get => _allSignedDataObjects;
		set
		{
			_allSignedDataObjects = value;
			if (_allSignedDataObjects)
			{
				_objectReferenceCollection.Clear();
			}
		}
	}

	/// <summary>
	/// The CommitmentTypeQualifiers element provides means to include additional
	/// qualifying information on the commitment made by the signer.
	/// </summary>
	public CommitmentTypeQualifiers CommitmentTypeQualifiers { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public CommitmentTypeIndication()
	{
		CommitmentTypeId = new ObjectIdentifier("CommitmentTypeId");
		_objectReferenceCollection = new ObjectReferenceCollection();
		_allSignedDataObjects = true;
		CommitmentTypeQualifiers = new CommitmentTypeQualifiers();
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (CommitmentTypeId != null && CommitmentTypeId.HasChanged())
		{
			result = true;
		}

		if (_objectReferenceCollection.Count > 0)
		{
			result = true;
		}

		if (CommitmentTypeQualifiers != null && CommitmentTypeQualifiers.HasChanged())
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
		xmlNamespaceManager.AddNamespace("xsd", XadesSignedXml.XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:CommitmentTypeId", xmlNamespaceManager);
		if (xmlNodeList is null
			|| xmlNodeList.Count <= 0)
		{
			throw new CryptographicException("CommitmentTypeId missing");
		}
		else
		{
			CommitmentTypeId = new ObjectIdentifier("CommitmentTypeId");
			CommitmentTypeId.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:ObjectReference", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			_objectReferenceCollection.Clear();
			_allSignedDataObjects = false;
			IEnumerator enumerator = xmlNodeList.GetEnumerator();
			try
			{
				while (enumerator.MoveNext())
				{
					if (enumerator.Current is not XmlElement iterationXmlElement)
					{
						continue;
					}

					var newObjectReference = new ObjectReference();
					newObjectReference.LoadXml(iterationXmlElement);
					_objectReferenceCollection.Add(newObjectReference);
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
		else
		{
			_objectReferenceCollection.Clear();
			_allSignedDataObjects = true;
		}

		xmlNodeList = xmlElement.SelectNodes("xsd:CommitmentTypeQualifiers", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			CommitmentTypeQualifiers = new CommitmentTypeQualifiers();
			CommitmentTypeQualifiers.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CommitmentTypeIndication", XadesSignedXml.XadesNamespaceUri);

		if (CommitmentTypeId != null && CommitmentTypeId.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(CommitmentTypeId.GetXml(), true));
		}
		else
		{
			throw new CryptographicException("CommitmentTypeId element missing");
		}

		if (_allSignedDataObjects)
		{
			//Add emty element as required
			XmlElement bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "AllSignedDataObjects", XadesSignedXml.XadesNamespaceUri);
			result.AppendChild(bufferXmlElement);
		}
		else
		{
			if (_objectReferenceCollection.Count > 0)
			{
				foreach (ObjectReference objectReference in _objectReferenceCollection)
				{
					if (objectReference.HasChanged())
					{
						result.AppendChild(creationXmlDocument.ImportNode(objectReference.GetXml(), true));
					}
				}
			}
		}

		if (CommitmentTypeQualifiers != null && CommitmentTypeQualifiers.HasChanged())
		{
			result.AppendChild(creationXmlDocument.ImportNode(CommitmentTypeQualifiers.GetXml(), true));
		}

		return result;
	}
}
