﻿// CRLValues.cs
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
using System.Xml;

namespace Microsoft.Xades;

/// <summary>
/// This class contains a collection of CRL values
/// </summary>
public class CRLValues
{
	/// <summary>
	/// Collection of CRLValues
	/// </summary>
	public CRLValueCollection CRLValueCollection { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public CRLValues()
	{
		CRLValueCollection = new CRLValueCollection();
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
		=> CRLValueCollection.Count > 0;

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

		CRLValueCollection.Clear();
		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:EncapsulatedCRLValue", xmlNamespaceManager);
		if (xmlNodeList is null)
		{
			throw new Exception($"Missing required EncapsulatedCRLValue element.");
		}

		IEnumerator enumerator = xmlNodeList.GetEnumerator();
		try
		{
			while (enumerator.MoveNext())
			{
				if (enumerator.Current is not XmlElement iterationXmlElement)
				{
					continue;
				}

				var newCRLValue = new CRLValue();
				newCRLValue.LoadXml(iterationXmlElement);
				CRLValueCollection.Add(newCRLValue);
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
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CRLValues", XadesSignedXml.XadesNamespaceUri);

		if (CRLValueCollection.Count > 0)
		{
			foreach (CRLValue crlValue in CRLValueCollection)
			{
				if (crlValue.HasChanged())
				{
					result.AppendChild(creationXmlDocument.ImportNode(crlValue.GetXml(), true));
				}
			}
		}

		return result;
	}
}
