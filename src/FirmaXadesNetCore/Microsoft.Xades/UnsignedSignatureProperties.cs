// UnsignedSignatureProperties.cs
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
/// UnsignedSignatureProperties may contain properties that qualify XML
/// signature itself or the signer
/// </summary>
public class UnsignedSignatureProperties
{
	private SignatureTimeStampCollection _archiveTimeStampCollection;

	/// <summary>
	/// A collection of counter signatures
	/// </summary>
	public CounterSignatureCollection CounterSignatureCollection { get; set; }

	/// <summary>
	/// A collection of signature timestamps
	/// </summary>
	public SignatureTimeStampCollection SignatureTimeStampCollection { get; set; }

	/// <summary>
	/// This clause defines the XML element containing the sequence of
	/// references to the full set of CA certificates that have been used
	/// to validate the electronic signature up to (but not including) the
	/// signer's certificate. This is an unsigned property that qualifies
	/// the signature.
	/// An XML electronic signature aligned with the present document MAY
	/// contain at most one CompleteCertificateRefs element.
	/// </summary>
	public CompleteCertificateRefs? CompleteCertificateRefs { get; set; }

	/// <summary>
	/// This clause defines the XML element containing a full set of
	/// references to the revocation data that have been used in the
	/// validation of the signer and CA certificates.
	/// This is an unsigned property that qualifies the signature.
	/// The XML electronic signature aligned with the present document
	/// MAY contain at most one CompleteRevocationRefs element.
	/// </summary>
	public CompleteRevocationRefs? CompleteRevocationRefs { get; set; }

	/// <summary>
	/// Flag indicating if the RefsOnlyTimeStamp element (or several) is
	/// present (RefsOnlyTimeStampFlag = true).  If one or more
	/// sigAndRefsTimeStamps are present, RefsOnlyTimeStampFlag will be false.
	/// </summary>
	public bool RefsOnlyTimeStampFlag { get; set; }

	/// <summary>
	/// A collection of sig and refs timestamps
	/// </summary>
	public SignatureTimeStampCollection SigAndRefsTimeStampCollection { get; set; }

	/// <summary>
	/// A collection of refs only timestamps
	/// </summary>
	public SignatureTimeStampCollection RefsOnlyTimeStampCollection { get; set; }

	/// <summary>
	/// Certificate values
	/// </summary>
	public CertificateValues? CertificateValues { get; set; }

	/// <summary>
	/// Revocation values
	/// </summary>
	public RevocationValues? RevocationValues { get; set; }

	/// <summary>
	/// A collection of signature timestamp
	/// </summary>
	public SignatureTimeStampCollection ArchiveTimeStampCollection
	{
		get => _archiveTimeStampCollection;
		set => _archiveTimeStampCollection = value;
	}

	/// <summary>
	/// Default constructor
	/// </summary>
	public UnsignedSignatureProperties()
	{
		CounterSignatureCollection = new CounterSignatureCollection();
		SignatureTimeStampCollection = new SignatureTimeStampCollection();
		CompleteCertificateRefs = new CompleteCertificateRefs();
		CompleteRevocationRefs = new CompleteRevocationRefs();
		RefsOnlyTimeStampFlag = false;
		SigAndRefsTimeStampCollection = new SignatureTimeStampCollection();
		RefsOnlyTimeStampCollection = new SignatureTimeStampCollection();
		CertificateValues = new CertificateValues();
		RevocationValues = new RevocationValues();
		_archiveTimeStampCollection = new SignatureTimeStampCollection();
	}

	/// <summary>
	/// Check to see if something has changed in this instance and needs to be serialized
	/// </summary>
	/// <returns>Flag indicating if a member needs serialization</returns>
	public bool HasChanged()
	{
		bool retVal = false;

		if (CounterSignatureCollection.Count > 0)
		{
			retVal = true;
		}

		if (SignatureTimeStampCollection.Count > 0)
		{
			retVal = true;
		}

		if (CompleteCertificateRefs != null && CompleteCertificateRefs.HasChanged())
		{
			retVal = true;
		}

		if (CompleteRevocationRefs != null && CompleteRevocationRefs.HasChanged())
		{
			retVal = true;
		}

		if (SigAndRefsTimeStampCollection.Count > 0)
		{
			retVal = true;
		}

		if (RefsOnlyTimeStampCollection.Count > 0)
		{
			retVal = true;
		}

		if (CertificateValues != null && CertificateValues.HasChanged())
		{
			retVal = true;
		}

		if (RevocationValues != null && RevocationValues.HasChanged())
		{
			retVal = true;
		}

		if (_archiveTimeStampCollection.Count > 0)
		{
			retVal = true;
		}

		return retVal;
	}

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">XML element containing new state</param>
	/// <param name="counterSignedXmlElement">Element containing parent signature (needed if there are counter signatures)</param>
	public void LoadXml(XmlElement? xmlElement, XmlElement? counterSignedXmlElement)
	{
		if (xmlElement is null)
		{
			throw new ArgumentNullException(nameof(xmlElement));
		}

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);
		xmlNamespaceManager.AddNamespace("xadesv141", XadesSignedXml.XadesNamespace141Uri);

		CounterSignatureCollection.Clear();
		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("xades:CounterSignature", xmlNamespaceManager);
		if (xmlNodeList is null)
		{
			throw new Exception($"Missing required counter signature.");
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

				XadesSignedXml newXadesSignedXml = counterSignedXmlElement != null
					? new XadesSignedXml(counterSignedXmlElement)
					: new XadesSignedXml();

				XmlElement? counterSignatureElement = null;
				for (int childNodeCounter = 0;
					(childNodeCounter < iterationXmlElement.ChildNodes.Count) && (counterSignatureElement == null);
					childNodeCounter++)
				{
					if (iterationXmlElement.ChildNodes[childNodeCounter] is XmlElement element)
					{
						counterSignatureElement = element;
					}
				}

				if (counterSignatureElement == null)
				{
					throw new CryptographicException("CounterSignature element does not contain signature");
				}

				newXadesSignedXml.LoadXml(counterSignatureElement);
				CounterSignatureCollection.Add(newXadesSignedXml);
			}
		}
		finally
		{
			if (enumerator is IDisposable disposable)
			{
				disposable.Dispose();
			}
		}

		SignatureTimeStampCollection.Clear();
		xmlNodeList = xmlElement.SelectNodes("xades:SignatureTimeStamp", xmlNamespaceManager);
		if (xmlNodeList is null)
		{
			throw new Exception($"Missing required signature timestamp.");
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

				newTimeStamp = new Timestamp("SignatureTimeStamp");
				newTimeStamp.LoadXml(iterationXmlElement);
				SignatureTimeStampCollection.Add(newTimeStamp);
			}
		}
		finally
		{
			if (enumerator is IDisposable disposable)
			{
				disposable.Dispose();
			}
		}

		xmlNodeList = xmlElement.SelectNodes("xades:CompleteCertificateRefs", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			CompleteCertificateRefs = new CompleteCertificateRefs();
			CompleteCertificateRefs.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}
		else
		{
			CompleteCertificateRefs = null;
		}

		xmlNodeList = xmlElement.SelectNodes("xades:CompleteRevocationRefs", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			CompleteRevocationRefs = new CompleteRevocationRefs();
			CompleteRevocationRefs.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}
		else
		{
			CompleteRevocationRefs = null;
		}

		SigAndRefsTimeStampCollection.Clear();
		RefsOnlyTimeStampCollection.Clear();

		xmlNodeList = xmlElement.SelectNodes("xades:SigAndRefsTimeStamp", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count > 0)
		{
			RefsOnlyTimeStampFlag = false;
			enumerator = xmlNodeList.GetEnumerator();
			try
			{
				while (enumerator.MoveNext())
				{
					if (enumerator.Current is not XmlElement iterationXmlElement)
					{
						continue;
					}

					newTimeStamp = new Timestamp("SigAndRefsTimeStamp");
					newTimeStamp.LoadXml(iterationXmlElement);
					SigAndRefsTimeStampCollection.Add(newTimeStamp);
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
			xmlNodeList = xmlElement.SelectNodes("xades:RefsOnlyTimeStamp", xmlNamespaceManager);
			if (xmlNodeList is not null
				&& xmlNodeList.Count > 0)
			{
				RefsOnlyTimeStampFlag = true;
				enumerator = xmlNodeList.GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
						if (enumerator.Current is not XmlElement iterationXmlElement)
						{
							continue;
						}

						newTimeStamp = new Timestamp("RefsOnlyTimeStamp");
						newTimeStamp.LoadXml(iterationXmlElement);
						RefsOnlyTimeStampCollection.Add(newTimeStamp);
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
				RefsOnlyTimeStampFlag = false;
			}
		}

		xmlNodeList = xmlElement.SelectNodes("xades:CertificateValues", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			CertificateValues = new CertificateValues();
			CertificateValues.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}
		else
		{
			CertificateValues = null;
		}

		xmlNodeList = xmlElement.SelectNodes("xades:RevocationValues", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count != 0)
		{
			RevocationValues = new RevocationValues();
			RevocationValues.LoadXml((XmlElement?)xmlNodeList.Item(0));
		}
		else
		{
			RevocationValues = null;
		}

		_archiveTimeStampCollection.Clear();
		xmlNodeList = xmlElement.SelectNodes("xades:ArchiveTimeStamp", xmlNamespaceManager);
		if (xmlNodeList is null)
		{
			throw new Exception($"Missing required ArchiveTimeStamp element.");
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

				newTimeStamp = new Timestamp("ArchiveTimeStamp");
				newTimeStamp.LoadXml(iterationXmlElement);
				_archiveTimeStampCollection.Add(newTimeStamp);
			}
		}
		finally
		{
			if (enumerator is IDisposable disposable)
			{
				disposable.Dispose();
			}
		}

		xmlNodeList = xmlElement.SelectNodes("xadesv141:ArchiveTimeStamp", xmlNamespaceManager);
		if (xmlNodeList is null)
		{
			throw new Exception($"Missing required ArchiveTimeStamp element.");
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

				newTimeStamp = new Timestamp("ArchiveTimeStamp", "xadesv141", XadesSignedXml.XadesNamespace141Uri);
				newTimeStamp.LoadXml(iterationXmlElement);
				_archiveTimeStampCollection.Add(newTimeStamp);
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
		XmlElement bufferXmlElement;

		creationXmlDocument = new XmlDocument();
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "UnsignedSignatureProperties", XadesSignedXml.XadesNamespaceUri);

		if (CounterSignatureCollection.Count > 0)
		{
			foreach (XadesSignedXml xadesSignedXml in CounterSignatureCollection)
			{
				bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CounterSignature", XadesSignedXml.XadesNamespaceUri);
				bufferXmlElement.AppendChild(creationXmlDocument.ImportNode(xadesSignedXml.GetXml(), true));
				retVal.AppendChild(creationXmlDocument.ImportNode(bufferXmlElement, true));
			}
		}

		if (SignatureTimeStampCollection.Count > 0)
		{
			foreach (Timestamp timeStamp in SignatureTimeStampCollection)
			{
				if (timeStamp.HasChanged())
				{
					retVal.AppendChild(creationXmlDocument.ImportNode(timeStamp.GetXml(), true));
				}
			}
		}

		if (CompleteCertificateRefs != null && CompleteCertificateRefs.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(CompleteCertificateRefs.GetXml(), true));
		}

		if (CompleteRevocationRefs != null && CompleteRevocationRefs.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(CompleteRevocationRefs.GetXml(), true));
		}

		if (!RefsOnlyTimeStampFlag)
		{
			foreach (Timestamp timeStamp in SigAndRefsTimeStampCollection)
			{
				if (timeStamp.HasChanged())
				{
					retVal.AppendChild(creationXmlDocument.ImportNode(timeStamp.GetXml(), true));
				}
			}
		}
		else
		{
			foreach (Timestamp timeStamp in RefsOnlyTimeStampCollection)
			{
				if (timeStamp.HasChanged())
				{
					retVal.AppendChild(creationXmlDocument.ImportNode(timeStamp.GetXml(), true));
				}
			}
		}

		if (CertificateValues != null && CertificateValues.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(CertificateValues.GetXml(), true));
		}

		if (RevocationValues != null && RevocationValues.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(RevocationValues.GetXml(), true));
		}

		if (_archiveTimeStampCollection.Count > 0)
		{
			foreach (Timestamp timeStamp in _archiveTimeStampCollection)
			{
				if (timeStamp.HasChanged())
				{
					retVal.AppendChild(creationXmlDocument.ImportNode(timeStamp.GetXml(), true));
				}
			}
		}

		return retVal;
	}
}
