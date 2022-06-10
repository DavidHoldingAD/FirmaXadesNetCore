// TimeStamp.cs
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

using System;
using System.Collections;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace Microsoft.Xades
{
	/// <summary>
	/// This class contains timestamp information
	/// </summary>
	public class TimeStamp
	{
		#region Private variables
		private string id;
		private string tagName;
		private HashDataInfoCollection hashDataInfoCollection;
		private EncapsulatedPKIData encapsulatedTimeStamp;
		private XMLTimeStamp xmlTimeStamp;
		private CanonicalizationMethod canonicalizationMethod;
		private string prefix;
		private string namespaceUri;
		#endregion

		#region Public properties
		/// <summary>
		/// The name of the element when serializing
		/// </summary>
		public string TagName
		{
			get
			{
				return this.tagName;
			}
			set
			{
				this.tagName = value;
			}
		}

		public string Id
		{
			get
			{
				return this.id;
			}
			set
			{
				this.id = value;
			}
		}

		/// <summary>
		/// A collection of hash data infos
		/// </summary>
		public HashDataInfoCollection HashDataInfoCollection
		{
			get
			{
				return this.hashDataInfoCollection;
			}
			set
			{
				this.hashDataInfoCollection = value;
			}
		}

		/// <summary>
		/// The time-stamp generated by a TSA encoded as an ASN.1 data
		/// object
		/// </summary>
		public EncapsulatedPKIData EncapsulatedTimeStamp
		{
			get
			{
				return this.encapsulatedTimeStamp;
			}
			set
			{
				this.encapsulatedTimeStamp = value;
				if (this.encapsulatedTimeStamp != null)
				{
					this.xmlTimeStamp = null;
				}
			}
		}

		/// <summary>
		/// The time-stamp generated by a TSA encoded as a generic XML
		/// timestamp
		/// </summary>
		public XMLTimeStamp XMLTimeStamp
		{
			get
			{
				return this.xmlTimeStamp;
			}
			set
			{
				this.xmlTimeStamp = value;
				if (this.xmlTimeStamp != null)
				{
					this.encapsulatedTimeStamp = null;
				}
			}
		}

		public CanonicalizationMethod CanonicalizationMethod
		{
			get
			{
				return this.canonicalizationMethod;
			}
			set
			{
				this.canonicalizationMethod = value;
			}
		}

		#endregion

		#region Constructors
		/// <summary>
		/// Default constructor
		/// </summary>
		public TimeStamp(string prefix, string namespaceUri)
		{
			this.hashDataInfoCollection = new HashDataInfoCollection();
			this.encapsulatedTimeStamp = new EncapsulatedPKIData("EncapsulatedTimeStamp");
			this.xmlTimeStamp = null;

			this.prefix = prefix;
			this.namespaceUri = namespaceUri;
		}

		/// <summary>
		/// Constructor with TagName
		/// </summary>
		/// <param name="tagName">Name of the tag when serializing with GetXml</param>
		public TimeStamp(string tagName)
			: this(XadesSignedXml.XmlXadesPrefix, XadesSignedXml.XadesNamespaceUri)
		{
			this.tagName = tagName;
		}

		/// <summary>
		/// Constructor with TagName and prefix
		/// </summary>
		/// <param name="tagName"></param>
		/// <param name="prefix"></param>
		/// <param name="namespaceUri"></param>
		public TimeStamp(string tagName, string prefix, string namespaceUri)
			: this(prefix, namespaceUri)
		{
			this.tagName = tagName;
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

			if (this.hashDataInfoCollection.Count > 0)
			{
				retVal = true;
			}

			if (this.encapsulatedTimeStamp != null && this.encapsulatedTimeStamp.HasChanged())
			{
				retVal = true;
			}

			if (this.xmlTimeStamp != null && this.xmlTimeStamp.HasChanged())
			{
				retVal = true;
			}

			return retVal;
		}

		/// <summary>
		/// Load state from an XML element
		/// </summary>
		/// <param name="xmlElement">XML element containing new state</param>
		public void LoadXml(System.Xml.XmlElement xmlElement)
		{
			XmlNamespaceManager xmlNamespaceManager;
			XmlNodeList xmlNodeList;
			IEnumerator enumerator;
			XmlElement iterationXmlElement;
			HashDataInfo newHashDataInfo;

			if (xmlElement == null)
			{
				throw new ArgumentNullException("xmlElement");
			}

			if (xmlElement.HasAttribute("Id"))
			{
				this.id = xmlElement.GetAttribute("Id");
			}
			else
			{
				this.id = "";
			}

			xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);
			xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

			this.hashDataInfoCollection.Clear();
			xmlNodeList = xmlElement.SelectNodes("xades:HashDataInfo", xmlNamespaceManager);
			enumerator = xmlNodeList.GetEnumerator();
			try
			{
				while (enumerator.MoveNext())
				{
					iterationXmlElement = enumerator.Current as XmlElement;
					if (iterationXmlElement != null)
					{
						newHashDataInfo = new HashDataInfo();
						newHashDataInfo.LoadXml(iterationXmlElement);
						this.hashDataInfoCollection.Add(newHashDataInfo);
					}
				}
			}
			finally
			{
				IDisposable disposable = enumerator as IDisposable;
				if (disposable != null)
				{
					disposable.Dispose();
				}
			}

			XmlNode canonicalizationNode = xmlElement.SelectSingleNode("ds:CanonicalizationMethod", xmlNamespaceManager);

			if (canonicalizationNode != null)
			{
				this.canonicalizationMethod = new CanonicalizationMethod();
				this.canonicalizationMethod.LoadXml((XmlElement)canonicalizationNode);
			}

			xmlNodeList = xmlElement.SelectNodes("xades:EncapsulatedTimeStamp", xmlNamespaceManager);

			if (xmlNodeList.Count != 0)
			{
				this.encapsulatedTimeStamp = new EncapsulatedPKIData("EncapsulatedTimeStamp");
				this.encapsulatedTimeStamp.LoadXml((XmlElement)xmlNodeList.Item(0));
				this.xmlTimeStamp = null;
			}
			else
			{
				XmlNode nodeEncapsulatedTimeStamp = null;

				foreach (XmlNode node in xmlElement.ChildNodes)
				{
					if (node.Name == "EncapsulatedTimeStamp")
					{
						nodeEncapsulatedTimeStamp = node;
						break;
					}
				}

				if (nodeEncapsulatedTimeStamp != null)
				{
					this.encapsulatedTimeStamp = new EncapsulatedPKIData("EncapsulatedTimeStamp");
					this.encapsulatedTimeStamp.LoadXml((XmlElement)nodeEncapsulatedTimeStamp);
					this.xmlTimeStamp = null;
				}
				else
				{
					xmlNodeList = xmlElement.SelectNodes("xades:XMLTimeStamp", xmlNamespaceManager);
					if (xmlNodeList.Count != 0)
					{
						this.xmlTimeStamp = new XMLTimeStamp();
						this.xmlTimeStamp.LoadXml((XmlElement)xmlNodeList.Item(0));
						this.encapsulatedTimeStamp = null;

					}
					else
					{
						throw new CryptographicException("EncapsulatedTimeStamp or XMLTimeStamp missing");
					}
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

			creationXmlDocument = new XmlDocument();

			retVal = creationXmlDocument.CreateElement(this.prefix, this.tagName, this.namespaceUri);

			//retVal.SetAttribute("xmlns:ds", SignedXml.XmlDsigNamespaceUrl);

			retVal.SetAttribute("Id", this.Id);

			/*  XmlElement canonicalization = creationXmlDocument.CreateElement("CanonicalizationMethod", SignedXml.XmlDsigNamespaceUrl);
              canonicalization.SetAttribute("Algorithm", "http://www.w3.org/TR/2001/REC-xml-c14n-20010315");

              retVal.AppendChild(canonicalization);*/

			//   XmlDsigC14NTransform xmlDsigC14NTransform = new XmlDsigC14NTransform();

			if (this.canonicalizationMethod != null)
			{
				retVal.AppendChild(creationXmlDocument.ImportNode(canonicalizationMethod.GetXml(), true));
			}

			if (this.hashDataInfoCollection.Count > 0)
			{
				foreach (HashDataInfo hashDataInfo in this.hashDataInfoCollection)
				{
					if (hashDataInfo.HasChanged())
					{
						retVal.AppendChild(creationXmlDocument.ImportNode(hashDataInfo.GetXml(), true));
					}
				}
			}

			if (this.encapsulatedTimeStamp != null && this.encapsulatedTimeStamp.HasChanged())
			{
				retVal.AppendChild(creationXmlDocument.ImportNode(this.encapsulatedTimeStamp.GetXml(), true));
			}
			else
			{
				if (this.xmlTimeStamp != null && this.xmlTimeStamp.HasChanged())
				{
					retVal.AppendChild(creationXmlDocument.ImportNode(this.xmlTimeStamp.GetXml(), true));
				}
				else
				{
					throw new CryptographicException("EncapsulatedTimeStamp or XMLTimeStamp element missing");
				}
			}

			return retVal;
		}
		#endregion
	}
}
