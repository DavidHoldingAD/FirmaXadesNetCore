// UnsignedSignatureProperties.cs
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
	#region Private variables
	private CounterSignatureCollection counterSignatureCollection;
	private SignatureTimeStampCollection signatureTimeStampCollection;
	private CompleteCertificateRefs completeCertificateRefs;
	private CompleteRevocationRefs completeRevocationRefs;
	private bool refsOnlyTimeStampFlag;
	private SignatureTimeStampCollection sigAndRefsTimeStampCollection;
	private SignatureTimeStampCollection refsOnlyTimeStampCollection;
	private CertificateValues certificateValues;
	private RevocationValues revocationValues;
	private SignatureTimeStampCollection archiveTimeStampCollection;
	#endregion

	#region Public properties
	/// <summary>
	/// A collection of counter signatures
	/// </summary>
	public CounterSignatureCollection CounterSignatureCollection
	{
		get
		{
			return counterSignatureCollection;
		}
		set
		{
			counterSignatureCollection = value;
		}
	}

	/// <summary>
	/// A collection of signature timestamps
	/// </summary>
	public SignatureTimeStampCollection SignatureTimeStampCollection
	{
		get
		{
			return signatureTimeStampCollection;
		}
		set
		{
			signatureTimeStampCollection = value;
		}
	}

	/// <summary>
	/// This clause defines the XML element containing the sequence of
	/// references to the full set of CA certificates that have been used
	/// to validate the electronic signature up to (but not including) the
	/// signer's certificate. This is an unsigned property that qualifies
	/// the signature.
	/// An XML electronic signature aligned with the present document MAY
	/// contain at most one CompleteCertificateRefs element.
	/// </summary>
	public CompleteCertificateRefs CompleteCertificateRefs
	{
		get
		{
			return completeCertificateRefs;
		}
		set
		{
			completeCertificateRefs = value;
		}
	}

	/// <summary>
	/// This clause defines the XML element containing a full set of
	/// references to the revocation data that have been used in the
	/// validation of the signer and CA certificates.
	/// This is an unsigned property that qualifies the signature.
	/// The XML electronic signature aligned with the present document
	/// MAY contain at most one CompleteRevocationRefs element.
	/// </summary>
	public CompleteRevocationRefs CompleteRevocationRefs
	{
		get
		{
			return completeRevocationRefs;
		}
		set
		{
			completeRevocationRefs = value;
		}
	}

	/// <summary>
	/// Flag indicating if the RefsOnlyTimeStamp element (or several) is
	/// present (RefsOnlyTimeStampFlag = true).  If one or more
	/// sigAndRefsTimeStamps are present, RefsOnlyTimeStampFlag will be false.
	/// </summary>
	public bool RefsOnlyTimeStampFlag
	{
		get
		{
			return refsOnlyTimeStampFlag;
		}
		set
		{
			refsOnlyTimeStampFlag = value;
		}
	}

	/// <summary>
	/// A collection of sig and refs timestamps
	/// </summary>
	public SignatureTimeStampCollection SigAndRefsTimeStampCollection
	{
		get
		{
			return sigAndRefsTimeStampCollection;
		}
		set
		{
			sigAndRefsTimeStampCollection = value;
		}
	}

	/// <summary>
	/// A collection of refs only timestamps
	/// </summary>
	public SignatureTimeStampCollection RefsOnlyTimeStampCollection
	{
		get
		{
			return refsOnlyTimeStampCollection;
		}
		set
		{
			refsOnlyTimeStampCollection = value;
		}
	}

	/// <summary>
	/// Certificate values
	/// </summary>
	public CertificateValues CertificateValues
	{
		get
		{
			return certificateValues;
		}
		set
		{
			certificateValues = value;
		}
	}

	/// <summary>
	/// Revocation values
	/// </summary>
	public RevocationValues RevocationValues
	{
		get
		{
			return revocationValues;
		}
		set
		{
			revocationValues = value;
		}
	}

	/// <summary>
	/// A collection of signature timestamp
	/// </summary>
	public SignatureTimeStampCollection ArchiveTimeStampCollection
	{
		get
		{
			return archiveTimeStampCollection;
		}
		set
		{
			archiveTimeStampCollection = value;
		}
	}
	#endregion

	#region Constructors
	/// <summary>
	/// Default constructor
	/// </summary>
	public UnsignedSignatureProperties()
	{
		counterSignatureCollection = new CounterSignatureCollection();
		signatureTimeStampCollection = new SignatureTimeStampCollection();
		completeCertificateRefs = new CompleteCertificateRefs();
		completeRevocationRefs = new CompleteRevocationRefs();
		refsOnlyTimeStampFlag = false;
		sigAndRefsTimeStampCollection = new SignatureTimeStampCollection();
		refsOnlyTimeStampCollection = new SignatureTimeStampCollection();
		certificateValues = new CertificateValues();
		revocationValues = new RevocationValues();
		archiveTimeStampCollection = new SignatureTimeStampCollection();
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

		if (counterSignatureCollection.Count > 0)
		{
			retVal = true;
		}

		if (signatureTimeStampCollection.Count > 0)
		{
			retVal = true;
		}

		if (completeCertificateRefs != null && completeCertificateRefs.HasChanged())
		{
			retVal = true;
		}

		if (completeRevocationRefs != null && completeRevocationRefs.HasChanged())
		{
			retVal = true;
		}

		if (sigAndRefsTimeStampCollection.Count > 0)
		{
			retVal = true;
		}

		if (refsOnlyTimeStampCollection.Count > 0)
		{
			retVal = true;
		}

		if (certificateValues != null && certificateValues.HasChanged())
		{
			retVal = true;
		}

		if (revocationValues != null && revocationValues.HasChanged())
		{
			retVal = true;
		}

		if (archiveTimeStampCollection.Count > 0)
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
	public void LoadXml(XmlElement xmlElement, XmlElement counterSignedXmlElement)
	{
		XmlNamespaceManager xmlNamespaceManager;
		XmlNodeList xmlNodeList;
		IEnumerator enumerator;
		XmlElement iterationXmlElement;
		XadesSignedXml newXadesSignedXml;
		TimeStamp newTimeStamp;
		XmlElement counterSignatureElement;

		if (xmlElement == null)
		{
			throw new ArgumentNullException("xmlElement");
		}

		xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);
		xmlNamespaceManager.AddNamespace("xadesv141", XadesSignedXml.XadesNamespace141Uri);

		counterSignatureCollection.Clear();
		xmlNodeList = xmlElement.SelectNodes("xades:CounterSignature", xmlNamespaceManager);
		enumerator = xmlNodeList.GetEnumerator();
		try
		{
			while (enumerator.MoveNext())
			{
				iterationXmlElement = enumerator.Current as XmlElement;
				if (iterationXmlElement != null)
				{
					if (counterSignedXmlElement != null)
					{
						newXadesSignedXml = new XadesSignedXml(counterSignedXmlElement);
					}
					else
					{
						newXadesSignedXml = new XadesSignedXml();
					}
					//Skip any whitespace at start
					counterSignatureElement = null;
					for (int childNodeCounter = 0; (childNodeCounter < iterationXmlElement.ChildNodes.Count) && (counterSignatureElement == null); childNodeCounter++)
					{
						if (iterationXmlElement.ChildNodes[childNodeCounter] is XmlElement)
						{
							counterSignatureElement = (XmlElement)iterationXmlElement.ChildNodes[childNodeCounter];
						}
					}
					if (counterSignatureElement != null)
					{
						newXadesSignedXml.LoadXml(counterSignatureElement);
						counterSignatureCollection.Add(newXadesSignedXml);
					}
					else
					{
						throw new CryptographicException("CounterSignature element does not contain signature");
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

		signatureTimeStampCollection.Clear();
		xmlNodeList = xmlElement.SelectNodes("xades:SignatureTimeStamp", xmlNamespaceManager);
		enumerator = xmlNodeList.GetEnumerator();
		try
		{
			while (enumerator.MoveNext())
			{
				iterationXmlElement = enumerator.Current as XmlElement;
				if (iterationXmlElement != null)
				{
					newTimeStamp = new TimeStamp("SignatureTimeStamp");
					newTimeStamp.LoadXml(iterationXmlElement);
					signatureTimeStampCollection.Add(newTimeStamp);
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

		xmlNodeList = xmlElement.SelectNodes("xades:CompleteCertificateRefs", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			completeCertificateRefs = new CompleteCertificateRefs();
			completeCertificateRefs.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		else
		{
			completeCertificateRefs = null;
		}

		xmlNodeList = xmlElement.SelectNodes("xades:CompleteRevocationRefs", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			CompleteRevocationRefs = new CompleteRevocationRefs();
			CompleteRevocationRefs.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		else
		{
			completeRevocationRefs = null;
		}

		sigAndRefsTimeStampCollection.Clear();
		refsOnlyTimeStampCollection.Clear();

		xmlNodeList = xmlElement.SelectNodes("xades:SigAndRefsTimeStamp", xmlNamespaceManager);
		if (xmlNodeList.Count > 0)
		{
			refsOnlyTimeStampFlag = false;
			enumerator = xmlNodeList.GetEnumerator();
			try
			{
				while (enumerator.MoveNext())
				{
					iterationXmlElement = enumerator.Current as XmlElement;
					if (iterationXmlElement != null)
					{
						newTimeStamp = new TimeStamp("SigAndRefsTimeStamp");
						newTimeStamp.LoadXml(iterationXmlElement);
						sigAndRefsTimeStampCollection.Add(newTimeStamp);
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
		else
		{
			xmlNodeList = xmlElement.SelectNodes("xades:RefsOnlyTimeStamp", xmlNamespaceManager);
			if (xmlNodeList.Count > 0)
			{
				refsOnlyTimeStampFlag = true;
				enumerator = xmlNodeList.GetEnumerator();
				try
				{
					while (enumerator.MoveNext())
					{
						iterationXmlElement = enumerator.Current as XmlElement;
						if (iterationXmlElement != null)
						{
							newTimeStamp = new TimeStamp("RefsOnlyTimeStamp");
							newTimeStamp.LoadXml(iterationXmlElement);
							refsOnlyTimeStampCollection.Add(newTimeStamp);
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
			else
			{
				refsOnlyTimeStampFlag = false;
			}
		}

		xmlNodeList = xmlElement.SelectNodes("xades:CertificateValues", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			certificateValues = new CertificateValues();
			certificateValues.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		else
		{
			certificateValues = null;
		}

		xmlNodeList = xmlElement.SelectNodes("xades:RevocationValues", xmlNamespaceManager);
		if (xmlNodeList.Count != 0)
		{
			revocationValues = new RevocationValues();
			revocationValues.LoadXml((XmlElement)xmlNodeList.Item(0));
		}
		else
		{
			revocationValues = null;
		}

		archiveTimeStampCollection.Clear();
		xmlNodeList = xmlElement.SelectNodes("xades:ArchiveTimeStamp", xmlNamespaceManager);

		enumerator = xmlNodeList.GetEnumerator();
		try
		{
			while (enumerator.MoveNext())
			{
				iterationXmlElement = enumerator.Current as XmlElement;
				if (iterationXmlElement != null)
				{
					newTimeStamp = new TimeStamp("ArchiveTimeStamp");
					newTimeStamp.LoadXml(iterationXmlElement);
					archiveTimeStampCollection.Add(newTimeStamp);
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

		xmlNodeList = xmlElement.SelectNodes("xadesv141:ArchiveTimeStamp", xmlNamespaceManager);

		enumerator = xmlNodeList.GetEnumerator();
		try
		{
			while (enumerator.MoveNext())
			{
				iterationXmlElement = enumerator.Current as XmlElement;
				if (iterationXmlElement != null)
				{
					newTimeStamp = new TimeStamp("ArchiveTimeStamp", "xadesv141", XadesSignedXml.XadesNamespace141Uri);
					newTimeStamp.LoadXml(iterationXmlElement);
					archiveTimeStampCollection.Add(newTimeStamp);
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
		XmlElement bufferXmlElement;

		creationXmlDocument = new XmlDocument();
		retVal = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "UnsignedSignatureProperties", XadesSignedXml.XadesNamespaceUri);

		if (counterSignatureCollection.Count > 0)
		{
			foreach (XadesSignedXml xadesSignedXml in counterSignatureCollection)
			{
				bufferXmlElement = creationXmlDocument.CreateElement(XadesSignedXml.XmlXadesPrefix, "CounterSignature", XadesSignedXml.XadesNamespaceUri);
				bufferXmlElement.AppendChild(creationXmlDocument.ImportNode(xadesSignedXml.GetXml(), true));
				retVal.AppendChild(creationXmlDocument.ImportNode(bufferXmlElement, true));
			}
		}

		if (signatureTimeStampCollection.Count > 0)
		{
			foreach (TimeStamp timeStamp in signatureTimeStampCollection)
			{
				if (timeStamp.HasChanged())
				{
					retVal.AppendChild(creationXmlDocument.ImportNode(timeStamp.GetXml(), true));
				}
			}
		}

		if (completeCertificateRefs != null && completeCertificateRefs.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(completeCertificateRefs.GetXml(), true));
		}

		if (completeRevocationRefs != null && completeRevocationRefs.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(completeRevocationRefs.GetXml(), true));
		}

		if (!refsOnlyTimeStampFlag)
		{
			foreach (TimeStamp timeStamp in sigAndRefsTimeStampCollection)
			{
				if (timeStamp.HasChanged())
				{
					retVal.AppendChild(creationXmlDocument.ImportNode(timeStamp.GetXml(), true));
				}
			}
		}
		else
		{
			foreach (TimeStamp timeStamp in refsOnlyTimeStampCollection)
			{
				if (timeStamp.HasChanged())
				{
					retVal.AppendChild(creationXmlDocument.ImportNode(timeStamp.GetXml(), true));
				}
			}
		}

		if (certificateValues != null && certificateValues.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(certificateValues.GetXml(), true));
		}

		if (revocationValues != null && revocationValues.HasChanged())
		{
			retVal.AppendChild(creationXmlDocument.ImportNode(revocationValues.GetXml(), true));
		}

		if (archiveTimeStampCollection.Count > 0)
		{
			foreach (TimeStamp timeStamp in archiveTimeStampCollection)
			{
				if (timeStamp.HasChanged())
				{
					retVal.AppendChild(creationXmlDocument.ImportNode(timeStamp.GetXml(), true));
				}
			}
		}

		return retVal;
	}
	#endregion
}
