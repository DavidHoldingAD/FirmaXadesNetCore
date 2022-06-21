// SignedDataObjectProperties.cs
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
/// The SignedDataObjectProperties element contains properties that qualify
/// some of the signed data objects
/// </summary>
public class SignedDataObjectProperties
{
	/// <summary>
	/// Collection of signed data object formats
	/// </summary>
	public DataObjectFormatCollection DataObjectFormatCollection { get; set; }

	/// <summary>
	/// Collection of commitment type indications
	/// </summary>
	public CommitmentTypeIndicationCollection CommitmentTypeIndicationCollection { get; set; }

	/// <summary>
	/// Collection of all data object timestamps
	/// </summary>
	public AllDataObjectsTimeStampCollection AllDataObjectsTimeStampCollection { get; set; }

	/// <summary>
	/// Collection of individual data object timestamps
	/// </summary>
	public IndividualDataObjectsTimeStampCollection IndividualDataObjectsTimeStampCollection { get; set; }

	/// <summary>
	/// Default constructor
	/// </summary>
	public SignedDataObjectProperties()
	{
		DataObjectFormatCollection = new DataObjectFormatCollection();
		CommitmentTypeIndicationCollection = new CommitmentTypeIndicationCollection();
		AllDataObjectsTimeStampCollection = new AllDataObjectsTimeStampCollection();
		IndividualDataObjectsTimeStampCollection = new IndividualDataObjectsTimeStampCollection();
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool result = false;

		if (DataObjectFormatCollection.Count > 0)
		{
			result = true;
		}

		if (CommitmentTypeIndicationCollection.Count > 0)
		{
			result = true;
		}

		if (AllDataObjectsTimeStampCollection.Count > 0)
		{
			result = true;
		}

		if (IndividualDataObjectsTimeStampCollection.Count > 0)
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

		DataObjectFormatCollection.Clear();
		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xsd:DataObjectFormat", xmlNamespaceManager);
		if (xmlNodeList is null)
		{
			throw new Exception($"Missing required DataObjectFormat element.");
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

				var newDataObjectFormat = new DataObjectFormat();
				newDataObjectFormat.LoadXml(iterationXmlElement);
				DataObjectFormatCollection.Add(newDataObjectFormat);
			}
		}
		finally
		{
			if (enumerator is IDisposable disposable)
			{
				disposable.Dispose();
			}
		}

		//this.dataObjectFormatCollection.Clear();
		xmlNodeList = xmlElement.SelectNodes("xsd:CommitmentTypeIndication", xmlNamespaceManager);
		if (xmlNodeList is null)
		{
			throw new Exception($"Missing required CommitmentTypeIndication element.");
		}

		enumerator = xmlNodeList.GetEnumerator();
		try
		{
			while (enumerator.MoveNext())
			{
				if (enumerator.Current is not XmlElement iterationXmlElement)
				{
					continue;
				}

				var newCommitmentTypeIndication = new CommitmentTypeIndication();
				newCommitmentTypeIndication.LoadXml(iterationXmlElement);
				CommitmentTypeIndicationCollection.Add(newCommitmentTypeIndication);
			}
		}
		finally
		{
			if (enumerator is IDisposable disposable)
			{
				disposable.Dispose();
			}
		}

		//this.dataObjectFormatCollection.Clear();
		xmlNodeList = xmlElement.SelectNodes("xsd:AllDataObjectsTimeStamp", xmlNamespaceManager);
		if (xmlNodeList is null)
		{
			throw new Exception($"Missing required AllDataObjectsTimeStamp element.");
		}

		enumerator = xmlNodeList.GetEnumerator();
		Timestamp newTimeStamp;
		try
		{
			while (enumerator.MoveNext())
			{
				if (enumerator.Current is not XmlElement iterationXmlElement)
				{
					continue;
				}

				newTimeStamp = new Timestamp("AllDataObjectsTimeStamp");
				newTimeStamp.LoadXml(iterationXmlElement);
				AllDataObjectsTimeStampCollection.Add(newTimeStamp);
			}
		}
		finally
		{
			if (enumerator is IDisposable disposable)
			{
				disposable.Dispose();
			}
		}

		//this.dataObjectFormatCollection.Clear();
		xmlNodeList = xmlElement.SelectNodes("xsd:IndividualDataObjectsTimeStamp", xmlNamespaceManager);
		if (xmlNodeList is null)
		{
			throw new Exception($"Missing required IndividualDataObjectsTimeStamp element.");
		}

		enumerator = xmlNodeList.GetEnumerator();
		try
		{
			while (enumerator.MoveNext())
			{
				if (enumerator.Current is not XmlElement iterationXmlElement)
				{
					continue;
				}

				newTimeStamp = new Timestamp("IndividualDataObjectsTimeStamp");
				newTimeStamp.LoadXml(iterationXmlElement);
				IndividualDataObjectsTimeStampCollection.Add(newTimeStamp);
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

		XmlElement result = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "SignedDataObjectProperties", XadesSignedXml.XadesNamespaceUri);

		if (DataObjectFormatCollection.Count > 0)
		{
			foreach (DataObjectFormat dataObjectFormat in DataObjectFormatCollection)
			{
				if (dataObjectFormat.HasChanged())
				{
					result.AppendChild(creationXmlDocument.ImportNode(dataObjectFormat.GetXml(), true));
				}
			}
		}

		if (CommitmentTypeIndicationCollection.Count > 0)
		{
			foreach (CommitmentTypeIndication commitmentTypeIndication in CommitmentTypeIndicationCollection)
			{
				if (commitmentTypeIndication.HasChanged())
				{
					result.AppendChild(creationXmlDocument.ImportNode(commitmentTypeIndication.GetXml(), true));
				}
			}
		}

		if (AllDataObjectsTimeStampCollection.Count > 0)
		{
			foreach (Timestamp timeStamp in AllDataObjectsTimeStampCollection)
			{
				if (timeStamp.HasChanged())
				{
					result.AppendChild(creationXmlDocument.ImportNode(timeStamp.GetXml(), true));
				}
			}
		}

		if (IndividualDataObjectsTimeStampCollection.Count > 0)
		{
			foreach (Timestamp timeStamp in IndividualDataObjectsTimeStampCollection)
			{
				if (timeStamp.HasChanged())
				{
					result.AppendChild(creationXmlDocument.ImportNode(timeStamp.GetXml(), true));
				}
			}
		}

		return result;
	}
}
