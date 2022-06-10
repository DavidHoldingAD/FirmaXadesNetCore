﻿// CommitmentTypeQualifier.cs
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
/// The CommitmentTypeQualifiers element provides means to include
/// additional qualifying information on the commitment made by the signer
/// </summary>
public class CommitmentTypeQualifier
{
	#region Private variables
	#endregion

	#region Public properties
	/// <summary>
	/// The generic XML element that represents a commitment type qualifier
	/// </summary>
	public XmlElement AnyXmlElement { get; set; }
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public CommitmentTypeQualifier()
	{
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

		if (AnyXmlElement != null)
		{
			retVal = true;
		}

		return retVal;
	}

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">XML element containing new state</param>
	public void LoadXml(XmlElement xmlElement) => AnyXmlElement = xmlElement;

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public XmlElement GetXml()
	{
		XmlDocument creationXmlDocument;
		XmlElement retVal;

		creationXmlDocument = new XmlDocument();
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CommitmentTypeQualifier", XadesSignedXml.XadesNamespaceUri);

		if (AnyXmlElement != null)
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(AnyXmlElement, true));
		}

		return retVal;
	}
	#endregion
}
