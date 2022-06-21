// SigPolicyQualifiers.cs
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
/// This class contains a collection of SigPolicyQualifiers
/// </summary>
public class SigPolicyQualifiers
{
	/// <summary>
	/// A collection of sig policy qualifiers
	/// </summary>
	public SigPolicyQualifierCollection SigPolicyQualifierCollection { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public SigPolicyQualifiers()
	{
		SigPolicyQualifierCollection = new SigPolicyQualifierCollection();
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
		=> SigPolicyQualifierCollection.Count > 0;

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

		SigPolicyQualifierCollection.Clear();
		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:SigPolicyQualifier", xmlNamespaceManager);
		if (xmlNodeList is null)
		{
			throw new Exception($"Missing required SigPolicyQualifier element.");
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

				var subElement = (XmlElement?)iterationXmlElement.SelectSingleNode("xsd:SPURI", xmlNamespaceManager);
				if (subElement != null)
				{
					var newSPUri = new SPUri();
					newSPUri.LoadXml(iterationXmlElement);
					SigPolicyQualifierCollection.Add(newSPUri);
				}
				else
				{
					var subElementNotice = (XmlElement?)iterationXmlElement.SelectSingleNode("xsd:SPUserNotice", xmlNamespaceManager);
					if (subElementNotice != null)
					{
						var newSPUserNotice = new SPUserNotice();
						newSPUserNotice.LoadXml(iterationXmlElement);
						SigPolicyQualifierCollection.Add(newSPUserNotice);
					}
					else
					{
						var newSigPolicyQualifier = new SigPolicyQualifier();
						newSigPolicyQualifier.LoadXml(iterationXmlElement);
						SigPolicyQualifierCollection.Add(newSigPolicyQualifier);
					}
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
		var creationXmlDocument = new XmlDocument();

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "SigPolicyQualifiers", XadesSignedXml.XadesNamespaceUri);

		if (SigPolicyQualifierCollection.Count > 0)
		{
			foreach (SigPolicyQualifier sigPolicyQualifier in SigPolicyQualifierCollection)
			{
				if (sigPolicyQualifier.HasChanged())
				{
					result.AppendChild(creationXmlDocument.ImportNode(sigPolicyQualifier.GetXml(), true));
				}
			}
		}

		return result;
	}
}
