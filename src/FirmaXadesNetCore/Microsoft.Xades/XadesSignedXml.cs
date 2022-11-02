// XadesSignedXml.cs
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
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Schema;
using FirmaXadesNetCore;

namespace Microsoft.Xades;

/// <summary>
/// Facade class for the XAdES signature library.  The class inherits from
/// the System.Security.Cryptography.Xml.SignedXml class and is backwards
/// compatible with it, so this class can host xmldsig signatures and XAdES
/// signatures.  The property SignatureStandard will indicate the type of the
/// signature: XMLDSIG or XAdES.
/// </summary>
public class XadesSignedXml : SignedXml
{
	private const string XadesXSDResourceName = "FirmaXadesNetCore.Microsoft.Xades.XAdES.xsd";
	private const string XmlDsigCoreXsdResourceName = "FirmaXadesNetCore.Microsoft.Xades.xmldsig-core-schema.xsd";

	/// <summary>
	/// The XAdES XML namespace URI
	/// </summary>
	public const string XadesNamespaceUri = "http://uri.etsi.org/01903/v1.3.2#";

	/// <summary>
	/// The XAdES v1.4.1 XML namespace URI
	/// </summary>
	public const string XadesNamespace141Uri = "http://uri.etsi.org/01903/v1.4.1#";

	/// <summary>
	/// Mandated type name for the Uri reference to the SignedProperties element
	/// </summary>
	public const string SignedPropertiesType = "http://uri.etsi.org/01903#SignedProperties";

	/// <summary>
	/// XMLDSIG object type
	/// </summary>
	public const string XmlDsigObjectType = "http://www.w3.org/2000/09/xmldsig#Object";

	#region Private variables

	private static readonly string[] _idAttributeNames = new string[]
	{
		"_id",
		"_Id",
		"_ID"
	};
	private XmlDocument? _cachedXadesObjectDocument;
	private string? _signedPropertiesIdBuffer;
	private string? _signedInfoIdBuffer;
	private readonly XmlDocument? _signatureDocument;

	#endregion

	#region Public properties

	// TODO: remove static

	/// <summary>
	/// Gets or sets the XML DSIG prefix.
	/// </summary>
	public static string XmlDSigPrefix { get; private set; } = "ds";

	/// <summary>
	/// Gets or sets the XML XAdES prefix.
	/// </summary>
	public static string XmlXadesPrefix { get; private set; } = "xades";

	/// <summary>
	/// Property indicating the type of signature (XmlDsig or XAdES)
	/// </summary>
	public KnownSignatureStandard SignatureStandard { get; private set; }

	/// <summary>
	/// Read-only property containing XAdES information
	/// </summary>
	public XadesObject XadesObject
	{
		get
		{
			var result = new XadesObject();
			result.LoadXml(GetXadesObjectElement(GetXml()), GetXml());

			return result;
		}
	}

	/// <summary>
	/// Setting this property will add an ID attribute to the SignatureValue element.
	/// This is required when constructing a XAdES-T signature.
	/// </summary>
	public string? SignatureValueId { get; set; }

	/// <summary>
	/// This property allows to access and modify the unsigned properties
	/// after the XAdES object has been added to the signature.
	/// Because the unsigned properties are part of a location in the
	/// signature that is not used when computing the signature, it is save
	/// to modify them even after the XMLDSIG signature has been computed.
	/// This is needed when XAdES objects that depend on the XMLDSIG
	/// signature value need to be added to the signature. The
	/// SignatureTimeStamp element is such a property, it can only be
	/// created when the XMLDSIG signature has been computed.
	/// </summary>
	public UnsignedProperties UnsignedProperties
	{
		get
		{
			DataObject? xadesDataObject = GetXadesDataObject();
			if (xadesDataObject is null)
			{
				throw new CryptographicException("XAdES object not found. Use AddXadesObject() before accessing UnsignedProperties.");
			}

			var result = new UnsignedProperties();
			XmlElement dataObjectXmlElement = xadesDataObject.GetXml();
			var xmlNamespaceManager = new XmlNamespaceManager(dataObjectXmlElement.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("xades", XadesNamespaceUri);
			XmlNodeList? xmlNodeList = dataObjectXmlElement.SelectNodes("xades:QualifyingProperties/xades:UnsignedProperties", xmlNamespaceManager);
			if (xmlNodeList is not null
				&& xmlNodeList.Count != 0)
			{
				result = new UnsignedProperties();
				result.LoadXml((XmlElement)xmlNodeList[0]!, (XmlElement)xmlNodeList[0]!);
			}

			return result;
		}
		set
		{
			DataObject? xadesDataObject = GetXadesDataObject();
			if (xadesDataObject is null)
			{
				throw new CryptographicException("XAdES object not found. Use AddXadesObject() before accessing UnsignedProperties.");
			}

			XmlElement dataObjectXmlElement = xadesDataObject.GetXml();
			var xmlNamespaceManager = new XmlNamespaceManager(dataObjectXmlElement.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("xades", XadesNamespaceUri);
			XmlNodeList? qualifyingPropertiesXmlNodeList = dataObjectXmlElement.SelectNodes("xades:QualifyingProperties", xmlNamespaceManager);
			XmlNodeList? unsignedPropertiesXmlNodeList = dataObjectXmlElement.SelectNodes("xades:QualifyingProperties/xades:UnsignedProperties", xmlNamespaceManager);
			if (unsignedPropertiesXmlNodeList is not null
				&& unsignedPropertiesXmlNodeList.Count != 0)
			{
				qualifyingPropertiesXmlNodeList![0]!.RemoveChild(unsignedPropertiesXmlNodeList[0]!);
			}
			XmlElement valueXml = value.GetXml();

			qualifyingPropertiesXmlNodeList![0]!.AppendChild(dataObjectXmlElement.OwnerDocument.ImportNode(valueXml, true));

			var newXadesDataObject = new DataObject();
			newXadesDataObject.LoadXml(dataObjectXmlElement);
			xadesDataObject.Data = newXadesDataObject.Data;
		}
	}

	/// <summary>
	/// Gets or sets the content element.
	/// </summary>
	public XmlElement? ContentElement { get; set; }

	/// <summary>
	/// Gets or sets the signature node destination element.
	/// </summary>
	public XmlElement? SignatureNodeDestination { get; set; }

	/// <summary>
	/// Gets or sets a flag indicating whether to add XAdES namespace.
	/// </summary>
	public bool AddXadesNamespace { get; set; }

	#endregion

	#region Constructors

	/// <summary>
	/// Default constructor for the XadesSignedXml class
	/// </summary>
	public XadesSignedXml()
		: base()
	{
		_cachedXadesObjectDocument = null;
		SignatureStandard = KnownSignatureStandard.XmlDsig;
	}

	/// <summary>
	/// Constructor for the XadesSignedXml class
	/// </summary>
	/// <param name="signatureElement">XmlElement used to create the instance</param>
	public XadesSignedXml(XmlElement signatureElement)
		: base(signatureElement)
	{
		_cachedXadesObjectDocument = null;
	}

	/// <summary>
	/// Constructor for the XadesSignedXml class
	/// </summary>
	/// <param name="signatureDocument">XmlDocument used to create the instance</param>
	public XadesSignedXml(XmlDocument signatureDocument)
		: base(signatureDocument)
	{
		_signatureDocument = signatureDocument;
		_cachedXadesObjectDocument = null;
	}

	#endregion

	#region Public methods

	/// <summary>
	/// Load state from an XML element
	/// </summary>
	/// <param name="xmlElement">The XML element from which to load the XadesSignedXml state</param>
	public new void LoadXml(XmlElement xmlElement)
	{
		_cachedXadesObjectDocument = null;
		SignatureValueId = null;
		base.LoadXml(xmlElement);

		// Get original prefix for namespaces
		foreach (XmlAttribute attr in xmlElement.Attributes)
		{
			if (attr.Name.StartsWith("xmlns"))
			{
				if (attr.Value.ToUpper() == XadesNamespaceUri.ToUpper())
				{
					XmlXadesPrefix = attr.Name.Split(':')[1];
				}
				else if (attr.Value.ToUpper() == XmlDsigNamespaceUrl.ToUpper())
				{
					XmlDSigPrefix = attr.Name.Split(':')[1];
				}
			}
		}

		XmlNode? idAttribute = xmlElement.Attributes.GetNamedItem("Id");
		if (idAttribute is not null)
		{
			Signature.Id = idAttribute.Value;
		}

		SetSignatureStandard(xmlElement);

		var xmlNamespaceManager = new XmlNamespaceManager(xmlElement.OwnerDocument.NameTable);

		xmlNamespaceManager.AddNamespace("ds", XmlDsigNamespaceUrl);
		xmlNamespaceManager.AddNamespace("xades", XadesNamespaceUri);

		XmlNodeList? xmlNodeList = xmlElement.SelectNodes("ds:SignatureValue", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count > 0)
		{
			if (((XmlElement)xmlNodeList[0]!).HasAttribute("Id"))
			{
				SignatureValueId = ((XmlElement)xmlNodeList[0]!).Attributes["Id"]?.Value;
			}
		}

		xmlNodeList = xmlElement.SelectNodes("ds:SignedInfo", xmlNamespaceManager);
		if (xmlNodeList is not null
			&& xmlNodeList.Count > 0)
		{
			_signedInfoIdBuffer = ((XmlElement)xmlNodeList[0]!).HasAttribute("Id")
				? (((XmlElement)xmlNodeList[0]!).Attributes["Id"]?.Value)
				: null;
		}
	}

	/// <summary>
	/// Returns the XML representation of the this object
	/// </summary>
	/// <returns>XML element containing the state of this object</returns>
	public new XmlElement GetXml()
	{
		XmlElement result = base.GetXml();

		// Add "ds" namespace prefix to all XmlDsig nodes in the signature
		SetPrefix(XmlDSigPrefix, result);

		var xmlNamespaceManager = new XmlNamespaceManager(result.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("ds", XmlDsigNamespaceUrl);

		if (SignatureValueId != null && SignatureValueId != "")
		{
			//Id on Signature value is needed for XAdES-T. We inject it here.
			xmlNamespaceManager = new XmlNamespaceManager(result.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("ds", XmlDsigNamespaceUrl);
			XmlNodeList? xmlNodeList = result.SelectNodes("ds:SignatureValue", xmlNamespaceManager);

			if (xmlNodeList is not null
				&& xmlNodeList.Count > 0
				&& xmlNodeList[0] is XmlElement signatureValueElement)
			{
				signatureValueElement.SetAttribute("Id", SignatureValueId);
			}
		}


		return result;
	}

	/// <summary>
	/// Overridden virtual method to be able to find the nested SignedProperties
	/// element inside of the XAdES object
	/// </summary>
	/// <param name="xmlDocument">Document in which to find the Id</param>
	/// <param name="idValue">Value of the Id to look for</param>
	/// <returns>XmlElement with requested Id</returns>
	public override XmlElement? GetIdElement(XmlDocument xmlDocument, string idValue)
	{
		if (xmlDocument is null)
		{
			return null;
		}

		XmlElement? result = base.GetIdElement(xmlDocument, idValue);
		if (result is not null)
		{
			return result;
		}

		foreach (string idAttributeName in _idAttributeNames)
		{
			XmlNode? xmlNode = xmlDocument
				.SelectSingleNode($"//*[@{idAttributeName}=\"{idValue}\"]");
			if (xmlNode is XmlElement xmlElement)
			{
				return xmlElement;
			}
		}

		return null;
	}

	/// <summary>
	/// Add a XAdES object to the signature
	/// </summary>
	/// <param name="xadesObject">XAdES object to add to signature</param>
	public void AddXadesObject(XadesObject xadesObject)
	{
		if (xadesObject is null)
		{
			throw new ArgumentNullException(nameof(xadesObject));
		}

		if (SignatureStandard == KnownSignatureStandard.Xades)
		{
			throw new CryptographicException("Can't add XAdES object, the signature already contains a XAdES object");
		}

		var dataObject = new DataObject
		{
			Id = xadesObject.Id,
			Data = xadesObject.GetXml().ChildNodes,
		};
		AddObject(dataObject); //Add the XAdES object                            

		var reference = new Reference();
		_signedPropertiesIdBuffer = xadesObject.QualifyingProperties.SignedProperties.Id;
		reference.Uri = "#" + _signedPropertiesIdBuffer;
		reference.Type = SignedPropertiesType;
		AddReference(reference); //Add the XAdES object reference

		_cachedXadesObjectDocument = new XmlDocument();
		XmlElement bufferXmlElement = xadesObject.GetXml();

		// Add "ds" namespace prefix to all XmlDsig nodes in the XAdES object
		SetPrefix("ds", bufferXmlElement);

		_cachedXadesObjectDocument.PreserveWhitespace = true;
		_cachedXadesObjectDocument.LoadXml(bufferXmlElement.OuterXml); //Cache to XAdES object for later use

		SignatureStandard = KnownSignatureStandard.Xades;
	}

	/// <summary>
	/// Additional tests for XAdES signatures.  These tests focus on
	/// XMLDSIG verification and correct form of the XAdES XML structure
	/// (schema validation and completeness as defined by the XAdES standard).
	/// </summary>
	/// <remarks>
	/// Because of the fact that the XAdES library is intentionally
	/// independent of standards like TSP (RFC3161) or OCSP (RFC2560),
	/// these tests do NOT include any verification of timestamps nor OCSP
	/// responses.
	/// These checks are important and have to be done in the application
	/// built on top of the XAdES library.
	/// </remarks>
	/// <exception cref="Exception">Thrown when the signature is not
	/// a XAdES signature.  SignatureStandard should be equal to
	/// <see cref="KnownSignatureStandard.Xades">KnownSignatureStandard.Xades</see>.
	/// Use the CheckSignature method for non-XAdES signatures.</exception>
	/// <param name="validationFlags">Bitmask to indicate which
	/// tests need to be done.  This function will call a public virtual
	/// methods for each bit that has been set in this mask.
	/// See the <see cref="XadesValidationFlags">XadesValidationFlags</see>
	/// enum for the bitmask definitions.  The virtual test method associated
	/// with a bit in the mask has the same name as enum value name.</param>
	/// <returns>If the function returns true the check was OK.  If the
	/// check fails an exception with a explanatory message is thrown.</returns>
	public bool CheckSignature(XadesValidationFlags validationFlags)
	{
		if (SignatureStandard != KnownSignatureStandard.Xades)
		{
			throw new Exception("SignatureStandard is not XAdES. CheckSignature returned: " + CheckSignature());
		}

		bool result = true;
		if (validationFlags.HasFlag(XadesValidationFlags.CheckXmldsigSignature))
		{
			result &= CheckXmldsigSignature();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.ValidateAgainstSchema))
		{
			result &= ValidateAgainstSchema();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckSameCertificate))
		{
			result &= CheckSameCertificate();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckAllReferencesExistInAllDataObjectsTimeStamp))
		{
			result &= CheckAllReferencesExistInAllDataObjectsTimeStamp();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckAllHashDataInfosInIndividualDataObjectsTimeStamp))
		{
			result &= CheckAllHashDataInfosInIndividualDataObjectsTimeStamp();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckCounterSignatures))
		{
			result &= CheckCounterSignatures(validationFlags);
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckCounterSignaturesReference))
		{
			result &= CheckCounterSignaturesReference();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckObjectReferencesInCommitmentTypeIndication))
		{
			result &= CheckObjectReferencesInCommitmentTypeIndication();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckIfClaimedRolesOrCertifiedRolesPresentInSignerRole))
		{
			result &= CheckIfClaimedRolesOrCertifiedRolesPresentInSignerRole();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckHashDataInfoOfSignatureTimeStampPointsToSignatureValue))
		{
			result &= CheckHashDataInfoOfSignatureTimeStampPointsToSignatureValue();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckQualifyingPropertiesTarget))
		{
			result &= CheckQualifyingPropertiesTarget();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckQualifyingProperties))
		{
			result &= CheckQualifyingProperties();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckSigAndRefsTimeStampHashDataInfos))
		{
			result &= CheckSigAndRefsTimeStampHashDataInfos();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckRefsOnlyTimeStampHashDataInfos))
		{
			result &= CheckRefsOnlyTimeStampHashDataInfos();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckArchiveTimeStampHashDataInfos))
		{
			result &= CheckArchiveTimeStampHashDataInfos();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckXadesCIsXadesT))
		{
			result &= CheckXadesCIsXadesT();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckXadesXLIsXadesX))
		{
			result &= CheckXadesXLIsXadesX();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckCertificateValuesMatchCertificateRefs))
		{
			result &= CheckCertificateValuesMatchCertificateRefs();
		}

		if (validationFlags.HasFlag(XadesValidationFlags.CheckRevocationValuesMatchRevocationRefs))
		{
			result &= CheckRevocationValuesMatchRevocationRefs();
		}

		return result;
	}

	/// <summary>
	/// Gets the signing certificate from the key information tag.
	/// </summary>
	/// <returns>the singing certificate</returns>
	public X509Certificate2 GetSigningCertificate()
	{
		byte[] bytes = GetSigningCertificateBytes();

		return new X509Certificate2(bytes);
	}

	/// <summary>
	/// Gets the signing certificate bytes from the key information tag.
	/// </summary>
	/// <returns>the singing certificate bytes</returns>
	public byte[] GetSigningCertificateBytes()
	{
		XmlNodeList certificateElements = KeyInfo
			.GetXml()
			.GetElementsByTagName("X509Certificate", XmlDsigNamespaceUrl);

		if (certificateElements is null
			|| certificateElements.Count <= 0
			|| certificateElements[0] is not XmlNode certificateElement)
		{
			throw new Exception("Failed to get signing certificate.");
		}

		return Convert.FromBase64String(certificateElement.InnerText);
	}

	#region XadesCheckSignature routines

	/// <summary>
	/// Check the signature of the underlying XMLDSIG signature
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckXmldsigSignature()
	{
		IEnumerable<XmlAttribute> namespaces = GetAllNamespaces(GetSignatureElement());

		if (KeyInfo == null)
		{
			var keyInfo = new KeyInfo();
			X509Certificate xmldsigCert = GetSigningCertificate();
			keyInfo.AddClause(new KeyInfoX509Data(xmldsigCert));
			KeyInfo = keyInfo;
		}

		foreach (Reference reference in SignedInfo.References)
		{
			foreach (System.Security.Cryptography.Xml.Transform transform in reference.TransformChain)
			{
				if (transform is not XmlDsigXPathTransform)
				{
					continue;
				}

				FieldInfo nsmFieldInfo = typeof(XmlDsigXPathTransform)
					.GetField("_nsm", BindingFlags.NonPublic | BindingFlags.Instance)!;
				var nsm = (XmlNamespaceManager)nsmFieldInfo.GetValue(transform)!;

				foreach (XmlAttribute ns in namespaces)
				{
					nsm.AddNamespace(ns.LocalName, ns.Value);
				}
			}
		}

		bool result = CheckDigestedReferences();
		if (result == false)
		{
			throw new CryptographicException("CheckXmldsigSignature() failed");
		}

		AsymmetricAlgorithm key = GetPublicKey();
		result = CheckSignedInfo(key);

		if (result == false)
		{
			throw new CryptographicException("CheckXmldsigSignature() failed");
		}

		return result;
	}

	/// <summary>
	/// Validate the XML representation of the signature against the XAdES and XMLDSIG schema.
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool ValidateAgainstSchema()
	{
		bool result = false;

		Assembly assembly = typeof(XadesSignedXml).Assembly;
		var schemaSet = new XmlSchemaSet();

		bool validationErrorOccurred = false;
		var validationErrorDescription = new System.Text.StringBuilder("");

		try
		{
			Stream? schemaStream = assembly.GetManifestResourceStream(XmlDsigCoreXsdResourceName);
			if (schemaStream is null)
			{
				throw new Exception($"Missing XML DSIG XSD embedded resource.");
			}

			void SchemaValidationHandler(object? sender, ValidationEventArgs validationEventArgs)
			{
				validationErrorOccurred = true;
				validationErrorDescription.AppendLine("Validation error:");
				validationErrorDescription.AppendLine($"\tSeverity: {validationEventArgs.Severity}");
				validationErrorDescription.AppendLine($"\tMessage: {validationEventArgs.Message}");
			}

			var handler = new ValidationEventHandler(SchemaValidationHandler);
			XmlSchema xmlSchema = XmlSchema.Read(schemaStream, handler)!;
			schemaSet.Add(xmlSchema);
			schemaStream.Close();

			schemaStream = assembly.GetManifestResourceStream(XadesXSDResourceName);
			if (schemaStream is null)
			{
				throw new Exception($"Missing XML XAdES XSD embedded resource.");
			}

			xmlSchema = XmlSchema.Read(schemaStream, handler)!;
			schemaSet.Add(xmlSchema);
			schemaStream.Close();

			if (validationErrorOccurred)
			{
				throw new CryptographicException($"Schema read validation error: {validationErrorDescription}");
			}
		}
		catch (Exception exception)
		{
			throw new CryptographicException("Problem during access of validation schema.", exception);
		}

		validationErrorDescription.Clear();

		void XmlValidationHandler(object? sender, ValidationEventArgs validationEventArgs)
		{
			if (validationEventArgs.Severity != XmlSeverityType.Warning)
			{
				validationErrorOccurred = true;
				validationErrorDescription.AppendLine("Validation error:");
				validationErrorDescription.AppendLine($"\tSeverity: {validationEventArgs.Severity.ToString()}");
				validationErrorDescription.AppendLine($"\tMessage: {validationEventArgs.Message}");
			}
		}

		var xmlReaderSettings = new XmlReaderSettings();
		xmlReaderSettings.ValidationEventHandler += new ValidationEventHandler(XmlValidationHandler);
		xmlReaderSettings.ValidationType = ValidationType.Schema;
		xmlReaderSettings.Schemas = schemaSet;
		xmlReaderSettings.ConformanceLevel = ConformanceLevel.Auto;

		var xadesNameTable = new NameTable();
		var xmlNamespaceManager = new XmlNamespaceManager(xadesNameTable);
		xmlNamespaceManager.AddNamespace("xsd", XadesNamespaceUri);

		var xmlParserContext = new XmlParserContext(null, xmlNamespaceManager, null, XmlSpace.None);

		var txtReader = new XmlTextReader(GetXml().OuterXml, XmlNodeType.Element, xmlParserContext);
		var reader = XmlReader.Create(txtReader, xmlReaderSettings);
		try
		{
			while (reader.Read())
			{
				;
			}

			if (validationErrorOccurred)
			{
				throw new CryptographicException($"Schema validation error: {validationErrorDescription}");
			}
		}
		catch (Exception exception)
		{
			throw new CryptographicException("Schema validation error", exception);
		}
		finally
		{
			reader.Close();
		}

		result = true;

		return result;
	}

	/// <summary>
	/// Check to see if first XMLDSIG certificate has same hash as first XAdES SignatureCertificate
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckSameCertificate()
	{
		CertCollection xadesSigningCertificateCollection = XadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties.SigningCertificate.CertCollection;
		if (xadesSigningCertificateCollection.Count <= 0)
		{
			throw new CryptographicException("Certificate not found in SigningCertificate element while doing CheckSameCertificate()");
		}

		DigestAlgAndValueType xadesCertificateDigest = xadesSigningCertificateCollection[0].CertDigest;

		X509Certificate2 keyInfoCertificate = GetSigningCertificate();
		HashAlgorithmName hashAlgorithmName = FirmaXadesNetCore.DigestMethod
			.GetByUri(xadesCertificateDigest.DigestMethod.Algorithm!)
			.GetHashAlgorithmName();
		ReadOnlySpan<byte> keyInfoCertificateHash = keyInfoCertificate.GetCertHash(hashAlgorithmName);

		if (!keyInfoCertificateHash.SequenceEqual(xadesCertificateDigest.DigestValue))
		{
			throw new CryptographicException("Certificate in XMLDSIG signature doesn't match certificate in SigningCertificate element");
		}

		return true;
	}

	/// <summary>
	/// Check if there is a HashDataInfo for each reference if there is a AllDataObjectsTimeStamp
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckAllReferencesExistInAllDataObjectsTimeStamp()
	{
		AllDataObjectsTimeStampCollection allDataObjectsTimeStampCollection;
		bool allHashDataInfosExist;
		Timestamp timeStamp;
		int timeStampCounter;
		bool retVal;

		allHashDataInfosExist = true;
		allDataObjectsTimeStampCollection = XadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties.AllDataObjectsTimeStampCollection;
		if (allDataObjectsTimeStampCollection.Count > 0)
		{
			for (timeStampCounter = 0; allHashDataInfosExist && (timeStampCounter < allDataObjectsTimeStampCollection.Count); timeStampCounter++)
			{
				timeStamp = allDataObjectsTimeStampCollection[timeStampCounter];
				allHashDataInfosExist &= CheckHashDataInfosForTimeStamp(timeStamp);
			}
			if (!allHashDataInfosExist)
			{
				throw new CryptographicException("At least one HashDataInfo is missing in AllDataObjectsTimeStamp element");
			}
		}
		retVal = true;

		return retVal;
	}

	/// <summary>
	/// Check if the HashDataInfo of each IndividualDataObjectsTimeStamp points to existing Reference
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckAllHashDataInfosInIndividualDataObjectsTimeStamp()
	{
		IndividualDataObjectsTimeStampCollection individualDataObjectsTimeStampCollection;
		bool hashDataInfoExists;
		Timestamp timeStamp;
		int timeStampCounter;
		bool retVal;

		hashDataInfoExists = true;
		individualDataObjectsTimeStampCollection = XadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties.IndividualDataObjectsTimeStampCollection;
		if (individualDataObjectsTimeStampCollection.Count > 0)
		{
			for (timeStampCounter = 0; hashDataInfoExists && (timeStampCounter < individualDataObjectsTimeStampCollection.Count); timeStampCounter++)
			{
				timeStamp = individualDataObjectsTimeStampCollection[timeStampCounter];
				hashDataInfoExists &= CheckHashDataInfosExist(timeStamp);
			}
			if (hashDataInfoExists == false)
			{
				throw new CryptographicException("At least one HashDataInfo is pointing to non-existing reference in IndividualDataObjectsTimeStamp element");
			}
		}
		retVal = true;

		return retVal;
	}

	/// <summary>
	/// Perform XAdES checks on contained counter signatures.  If couter signature is XMLDSIG, only XMLDSIG check (CheckSignature()) is done.
	/// </summary>
	/// <param name="validationFlags">Check mask applied to counter signatures</param>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckCounterSignatures(XadesValidationFlags validationFlags)
	{
		CounterSignatureCollection counterSignatureCollection;
		XadesSignedXml counterSignature;
		bool retVal;

		retVal = true;
		counterSignatureCollection = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.CounterSignatureCollection;
		for (int counterSignatureCounter = 0; (retVal == true) && (counterSignatureCounter < counterSignatureCollection.Count); counterSignatureCounter++)
		{
			counterSignature = counterSignatureCollection[counterSignatureCounter];
			//TODO: check if parent signature document is present in counterSignature (maybe a deep copy is required)
			if (counterSignature.SignatureStandard == KnownSignatureStandard.Xades)
			{
				retVal &= counterSignature.CheckSignature(validationFlags);
			}
			else
			{
				retVal &= counterSignature.CheckSignature();
			}
		}
		if (retVal == false)
		{
			throw new CryptographicException("XadesCheckSignature() failed on at least one counter signature");
		}
		retVal = true;

		return retVal;
	}

	/// <summary>
	/// Counter signatures should all contain a reference to the parent signature SignatureValue element
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckCounterSignaturesReference()
	{
		CounterSignatureCollection counterSignatureCollection;
		XadesSignedXml counterSignature;
		string referenceUri;
		ArrayList parentSignatureValueChain;
		bool referenceToParentSignatureFound;
		bool retVal;

		retVal = true;
		parentSignatureValueChain = new ArrayList
		{
			$"#{SignatureValueId}",
		};
		counterSignatureCollection = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.CounterSignatureCollection;
		for (int counterSignatureCounter = 0; (retVal == true) && (counterSignatureCounter < counterSignatureCollection.Count); counterSignatureCounter++)
		{
			counterSignature = counterSignatureCollection[counterSignatureCounter];
			referenceToParentSignatureFound = false;
			for (int referenceCounter = 0; referenceToParentSignatureFound == false && (referenceCounter < counterSignature.SignedInfo.References.Count); referenceCounter++)
			{
				referenceUri = ((Reference)counterSignature.SignedInfo.References![referenceCounter]!).Uri;
				if (parentSignatureValueChain.BinarySearch(referenceUri) >= 0)
				{
					referenceToParentSignatureFound = true;
				}
				parentSignatureValueChain.Add("#" + counterSignature.SignatureValueId);
				parentSignatureValueChain.Sort();
			}
			retVal = referenceToParentSignatureFound;
		}
		if (retVal == false)
		{
			throw new CryptographicException("CheckCounterSignaturesReference() failed on at least one counter signature");
		}
		retVal = true;

		return retVal;
	}

	/// <summary>
	/// Check if each ObjectReference in CommitmentTypeIndication points to Reference element
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckObjectReferencesInCommitmentTypeIndication()
	{
		CommitmentTypeIndicationCollection commitmentTypeIndicationCollection;
		CommitmentTypeIndication commitmentTypeIndication;
		bool objectReferenceOK;
		bool retVal;

		retVal = true;
		commitmentTypeIndicationCollection = XadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties.CommitmentTypeIndicationCollection;
		if (commitmentTypeIndicationCollection.Count > 0)
		{
			for (int commitmentTypeIndicationCounter = 0; (retVal == true) && (commitmentTypeIndicationCounter < commitmentTypeIndicationCollection.Count); commitmentTypeIndicationCounter++)
			{
				commitmentTypeIndication = commitmentTypeIndicationCollection[commitmentTypeIndicationCounter];
				objectReferenceOK = true;
				foreach (ObjectReference objectReference in commitmentTypeIndication.ObjectReferenceCollection)
				{
					objectReferenceOK &= CheckObjectReference(objectReference);
				}
				retVal = objectReferenceOK;
			}
			if (retVal == false)
			{
				throw new CryptographicException("At least one ObjectReference in CommitmentTypeIndication did not point to a Reference");
			}
		}

		return retVal;
	}

	/// <summary>
	/// Check if at least ClaimedRoles or CertifiedRoles present in SignerRole
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckIfClaimedRolesOrCertifiedRolesPresentInSignerRole()
	{
		SignerRole? signerRole = XadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties.SignerRole;
		if (signerRole == null)
		{
			return true;
		}

		bool result = false;

		if (signerRole.CertifiedRoles != null)
		{
			result = signerRole.CertifiedRoles.CertifiedRoleCollection.Count > 0;
		}

		if (result == false)
		{
			if (signerRole.ClaimedRoles != null)
			{
				result = signerRole.ClaimedRoles.ClaimedRoleCollection.Count > 0;
			}
		}

		if (result == false)
		{
			throw new CryptographicException("SignerRole element must contain at least one CertifiedRole or ClaimedRole element");
		}

		return result;
	}

	/// <summary>
	/// Check if HashDataInfo of SignatureTimeStamp points to SignatureValue
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckHashDataInfoOfSignatureTimeStampPointsToSignatureValue()
	{
		SignatureTimeStampCollection signatureTimeStampCollection;
		bool hashDataInfoPointsToSignatureValue;
		Timestamp timeStamp;
		int timeStampCounter;
		bool retVal;

		hashDataInfoPointsToSignatureValue = true;
		signatureTimeStampCollection = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection;
		if (signatureTimeStampCollection.Count > 0)
		{
			for (timeStampCounter = 0; hashDataInfoPointsToSignatureValue && (timeStampCounter < signatureTimeStampCollection.Count); timeStampCounter++)
			{
				timeStamp = signatureTimeStampCollection[timeStampCounter];
				hashDataInfoPointsToSignatureValue &= CheckHashDataInfoPointsToSignatureValue(timeStamp);
			}
			if (hashDataInfoPointsToSignatureValue == false)
			{
				throw new CryptographicException("HashDataInfo of SignatureTimeStamp doesn't point to signature value element");
			}
		}
		retVal = true;

		return retVal;
	}

	/// <summary>
	/// Check if the QualifyingProperties Target attribute points to the signature element
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckQualifyingPropertiesTarget()
	{
		bool result = true;
		if (Signature.Id == null)
		{
			result = false;
		}
		else
		{
			string? qualifyingPropertiesTarget = XadesObject.QualifyingProperties.Target;
			if (qualifyingPropertiesTarget != $"#{Signature.Id}")
			{
				result = false;
			}
		}

		if (result == false)
		{
			throw new CryptographicException("Qualifying properties target doesn't point to signature element or signature element doesn't have an Id");
		}

		return result;
	}

	/// <summary>
	/// Check that QualifyingProperties occur in one Object, check that there is only one QualifyingProperties and that signed properties occur in one QualifyingProperties element
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckQualifyingProperties()
	{
		XmlElement signatureElement = GetXml();

		var xmlNamespaceManager = new XmlNamespaceManager(signatureElement.OwnerDocument.NameTable);
		xmlNamespaceManager.AddNamespace("ds", XmlDsigNamespaceUrl);
		xmlNamespaceManager.AddNamespace("xsd", XadesNamespaceUri);
		XmlNodeList? xmlNodeList = signatureElement.SelectNodes("ds:Object/xsd:QualifyingProperties", xmlNamespaceManager);

		if (xmlNodeList is not null
			&& xmlNodeList.Count > 1)
		{
			throw new CryptographicException("More than one Object contains a QualifyingProperties element");
		}

		return true;
	}

	/// <summary>
	/// Check if all required HashDataInfos are present on SigAndRefsTimeStamp
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckSigAndRefsTimeStampHashDataInfos()
	{
		SignatureTimeStampCollection signatureTimeStampCollection;
		Timestamp timeStamp;
		bool allRequiredhashDataInfosFound;
		bool retVal;

		retVal = true;
		signatureTimeStampCollection = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.SigAndRefsTimeStampCollection;
		if (signatureTimeStampCollection.Count > 0)
		{
			allRequiredhashDataInfosFound = true;
			for (int timeStampCounter = 0; allRequiredhashDataInfosFound && (timeStampCounter < signatureTimeStampCollection.Count); timeStampCounter++)
			{
				timeStamp = signatureTimeStampCollection[timeStampCounter];
				allRequiredhashDataInfosFound &= CheckHashDataInfosOfSigAndRefsTimeStamp(timeStamp);
			}
			if (allRequiredhashDataInfosFound == false)
			{
				throw new CryptographicException("At least one required HashDataInfo is missing in a SigAndRefsTimeStamp element");
			}
		}

		return retVal;
	}

	/// <summary>
	/// Check if all required HashDataInfos are present on RefsOnlyTimeStamp
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckRefsOnlyTimeStampHashDataInfos()
	{
		SignatureTimeStampCollection signatureTimeStampCollection;
		Timestamp timeStamp;
		bool allRequiredhashDataInfosFound;
		bool retVal;

		retVal = true;
		signatureTimeStampCollection = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.RefsOnlyTimeStampCollection;
		if (signatureTimeStampCollection.Count > 0)
		{
			allRequiredhashDataInfosFound = true;
			for (int timeStampCounter = 0; allRequiredhashDataInfosFound && (timeStampCounter < signatureTimeStampCollection.Count); timeStampCounter++)
			{
				timeStamp = signatureTimeStampCollection[timeStampCounter];
				allRequiredhashDataInfosFound &= CheckHashDataInfosOfRefsOnlyTimeStamp(timeStamp);
			}
			if (allRequiredhashDataInfosFound == false)
			{
				throw new CryptographicException("At least one required HashDataInfo is missing in a RefsOnlyTimeStamp element");
			}
		}

		return retVal;
	}

	/// <summary>
	/// Check if all required HashDataInfos are present on ArchiveTimeStamp
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckArchiveTimeStampHashDataInfos()
	{
		SignatureTimeStampCollection signatureTimeStampCollection;
		Timestamp timeStamp;
		bool allRequiredhashDataInfosFound;
		bool retVal;

		retVal = true;
		signatureTimeStampCollection = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.ArchiveTimeStampCollection;
		if (signatureTimeStampCollection.Count > 0)
		{
			allRequiredhashDataInfosFound = true;
			for (int timeStampCounter = 0; allRequiredhashDataInfosFound && (timeStampCounter < signatureTimeStampCollection.Count); timeStampCounter++)
			{
				timeStamp = signatureTimeStampCollection[timeStampCounter];
				allRequiredhashDataInfosFound &= CheckHashDataInfosOfArchiveTimeStamp(timeStamp);
			}
			if (allRequiredhashDataInfosFound == false)
			{
				throw new CryptographicException("At least one required HashDataInfo is missing in a ArchiveTimeStamp element");
			}
		}

		return retVal;
	}

	/// <summary>
	/// Check if a XAdES-C signature is also a XAdES-T signature
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckXadesCIsXadesT()
	{
		UnsignedSignatureProperties unsignedSignatureProperties;
		bool retVal;

		retVal = true;
		unsignedSignatureProperties = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
		if (((unsignedSignatureProperties.CompleteCertificateRefs != null) && (unsignedSignatureProperties.CompleteCertificateRefs.HasChanged()))
			|| ((unsignedSignatureProperties.CompleteCertificateRefs != null) && (unsignedSignatureProperties.CompleteCertificateRefs.HasChanged())))
		{
			if (unsignedSignatureProperties.SignatureTimeStampCollection.Count == 0)
			{
				throw new CryptographicException("XAdES-C signature should also contain a SignatureTimeStamp element");
			}
		}

		return retVal;
	}

	/// <summary>
	/// Check if a XAdES-XL signature is also a XAdES-X signature
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckXadesXLIsXadesX()
	{
		UnsignedSignatureProperties unsignedSignatureProperties;
		bool retVal;

		retVal = true;
		unsignedSignatureProperties = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
		if (((unsignedSignatureProperties.CertificateValues != null) && (unsignedSignatureProperties.CertificateValues.HasChanged()))
			|| ((unsignedSignatureProperties.RevocationValues != null) && (unsignedSignatureProperties.RevocationValues.HasChanged())))
		{
			if ((unsignedSignatureProperties.SigAndRefsTimeStampCollection.Count == 0) && (unsignedSignatureProperties.RefsOnlyTimeStampCollection.Count == 0))
			{
				throw new CryptographicException("XAdES-XL signature should also contain a XAdES-X element");
			}
		}

		return retVal;
	}

	/// <summary>
	/// Check if CertificateValues match CertificateRefs
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckCertificateValuesMatchCertificateRefs()
	{
		//TODO: Similar test should be done for XML based (Other) certificates, but as the check needed is not known, there is no implementation
		UnsignedSignatureProperties unsignedSignatureProperties = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
		if (unsignedSignatureProperties.CompleteCertificateRefs == null || unsignedSignatureProperties.CompleteCertificateRefs.CertRefs == null ||
			unsignedSignatureProperties.CertificateValues == null)
		{
			return true;
		}

		bool result = true;
		var certDigests = new ArrayList();
		foreach (Cert cert in unsignedSignatureProperties.CompleteCertificateRefs.CertRefs.CertCollection)
		{
			certDigests.Add(Convert.ToBase64String(cert.CertDigest.DigestValue!));
		}

		certDigests.Sort();
		foreach (EncapsulatedX509Certificate encapsulatedX509Certificate in unsignedSignatureProperties.CertificateValues.EncapsulatedX509CertificateCollection)
		{
			byte[] certDigest = HashSha1(encapsulatedX509Certificate.PkiData!);
			int index = certDigests.BinarySearch(Convert.ToBase64String(certDigest));
			if (index >= 0)
			{
				certDigests.RemoveAt(index);
			}
		}

		if (certDigests.Count != 0)
		{
			throw new CryptographicException("Not all CertificateRefs correspond to CertificateValues");
		}

		return result;
	}

	/// <summary>
	/// Check if RevocationValues match RevocationRefs
	/// </summary>
	/// <returns>If the function returns true the check was OK</returns>
	public virtual bool CheckRevocationValuesMatchRevocationRefs()
	{
		//TODO: Similar test should be done for XML based (Other) revocation information and OCSP
		//responses, but to keep the library independent of these technologies, this
		//test is left to applications using the library

		UnsignedSignatureProperties unsignedSignatureProperties = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
		if (unsignedSignatureProperties.CompleteRevocationRefs == null
			|| unsignedSignatureProperties.CompleteRevocationRefs.CRLRefs == null ||
			unsignedSignatureProperties.RevocationValues == null)
		{
			return true;
		}

		bool result = true;
		var crlDigests = new ArrayList();

		foreach (CRLRef crlRef in unsignedSignatureProperties.CompleteRevocationRefs.CRLRefs.CRLRefCollection)
		{
			crlDigests.Add(Convert.ToBase64String(crlRef.CertDigest.DigestValue!));
		}

		crlDigests.Sort();
		foreach (CRLValue crlValue in unsignedSignatureProperties.RevocationValues.CRLValues.CRLValueCollection)
		{
			byte[] crlDigest = HashSha1(crlValue.PkiData!);
			int index = crlDigests.BinarySearch(Convert.ToBase64String(crlDigest));
			if (index >= 0)
			{
				crlDigests.RemoveAt(index);
			}
		}

		if (crlDigests.Count != 0)
		{
			throw new CryptographicException("Not all RevocationRefs correspond to RevocationValues");
		}

		return result;
	}

	#endregion

	#endregion

	#region Fix to add a namespace prefix for all XmlDsig nodes

	private void SetPrefix(string prefix, XmlNode node)
	{
		if (node.NamespaceURI == XmlDsigNamespaceUrl)
		{
			node.Prefix = prefix;
		}

		foreach (XmlNode child in node.ChildNodes)
		{
			SetPrefix(prefix, child);
		}

		return;
	}

	/// <inheritdoc/>
	public new byte[] ComputeSignature()
	{
		BuildDigestedReferences();

		AsymmetricAlgorithm signingKey = SigningKey;
		if (signingKey == null)
		{
			throw new CryptographicException("Cryptography_Xml_LoadKeyFailed");
		}
		if (SignedInfo.SignatureMethod == null)
		{
			if (signingKey is not DSA)
			{
				if (signingKey is not RSA)
				{
					throw new CryptographicException("Cryptography_Xml_CreatedKeyFailed");
				}
				if (SignedInfo.SignatureMethod == null)
				{
					SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
				}
			}
			else
			{
				SignedInfo.SignatureMethod = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
			}
		}

		SignatureDescription description = FirmaXadesNetCore.SignatureMethod
			.GetByUri(SignedInfo.SignatureMethod)
			.Create();
		if (description == null)
		{
			throw new CryptographicException("Cryptography_Xml_SignatureDescriptionNotCreated");
		}

		HashAlgorithm? hashAlgorithm = description.CreateDigest();
		if (hashAlgorithm is null)
		{
			throw new CryptographicException("Cryptography_Xml_CreateHashAlgorithmFailed");
		}

		byte[] digest = GetC14NDigest(hashAlgorithm, "ds");

		m_signature.SignatureValue = description.CreateFormatter(signingKey).CreateSignature(hashAlgorithm);

		return digest;
	}

	/// <summary>
	/// Gets the content reference.
	/// </summary>
	/// <returns>the reference</returns>
	public Reference GetContentReference()
	{
		XadesObject xadesObject;
		if (_cachedXadesObjectDocument != null)
		{
			xadesObject = new XadesObject();
			xadesObject.LoadXml(_cachedXadesObjectDocument.DocumentElement, null);
		}
		else
		{
			xadesObject = XadesObject;
		}

		if (xadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties.DataObjectFormatCollection.Count > 0)
		{
			string? referenceId = xadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties
				.DataObjectFormatCollection![0]
				?.ObjectReferenceAttribute
				?.Substring(1);

			foreach (object reference in SignedInfo.References)
			{
				if (((Reference)reference).Id == referenceId)
				{
					return (Reference)reference;
				}
			}
		}

		return (Reference)SignedInfo.References[0]!;
	}

	/// <summary>
	/// Finds the content element.
	/// </summary>
	public void FindContentElement()
	{
		Reference contentRef = GetContentReference();

		if (!string.IsNullOrEmpty(contentRef.Uri) &&
			contentRef.Uri.StartsWith("#"))
		{
			ContentElement = GetIdElement(_signatureDocument!, contentRef.Uri.Substring(1));
		}
		else
		{
			ContentElement = _signatureDocument!.DocumentElement;
		}
	}

	/// <summary>
	/// Gets the signature XML element.
	/// </summary>
	/// <returns>the element</returns>
	public XmlElement? GetSignatureElement()
	{
		XmlElement? signatureElement = GetIdElement(_signatureDocument!, Signature.Id);

		if (signatureElement != null)
		{
			return signatureElement;
		}

		if (SignatureNodeDestination != null)
		{
			return SignatureNodeDestination;
		}

		if (ContentElement == null)
		{
			return null;
		}

		if (ContentElement!.ParentNode!.NodeType != XmlNodeType.Document)
		{
			return (XmlElement)ContentElement.ParentNode;
		}
		else
		{
			return ContentElement;
		}
	}

	/// <summary>
	/// Gets all namespaces from the specified element.
	/// </summary>
	/// <param name="fromElement">the from element</param>
	/// <returns>the namespace attributes</returns>
	public List<XmlAttribute> GetAllNamespaces(XmlElement? fromElement)
	{
		var namespaces = new List<XmlAttribute>();

		if (fromElement != null
			&& fromElement.ParentNode!.NodeType == XmlNodeType.Document)
		{
			foreach (XmlAttribute attr in fromElement.Attributes)
			{
				if (attr.Name.StartsWith("xmlns") && !namespaces.Exists(f => f.Name == attr.Name))
				{
					namespaces.Add(attr);
				}
			}

			return namespaces;
		}

		XmlNode? currentNode = fromElement;
		while (currentNode != null && currentNode.NodeType != XmlNodeType.Document)
		{
			foreach (XmlAttribute attr in currentNode.Attributes!)
			{
				if (attr.Name.StartsWith("xmlns") && !namespaces.Exists(f => f.Name == attr.Name))
				{
					namespaces.Add(attr);
				}
			}

			currentNode = currentNode.ParentNode;
		}

		return namespaces;
	}

	/// <summary>
	/// Copy of System.Security.Cryptography.Xml.SignedXml.BuildDigestedReferences() which will add a "ds" 
	/// namespace prefix to all XmlDsig nodes
	/// </summary>
	private void BuildDigestedReferences()
	{
		ArrayList references = SignedInfo.References;

		//this.m_refProcessed = new bool[references.Count];
		Type SignedXml_Type = typeof(SignedXml);
		FieldInfo SignedXml_m_refProcessed = SignedXml_Type.GetField("_refProcessed", BindingFlags.NonPublic | BindingFlags.Instance)!;
		SignedXml_m_refProcessed.SetValue(this, new bool[references.Count]);
		//

		//this.m_refLevelCache = new int[references.Count];
		FieldInfo SignedXml_m_refLevelCache = SignedXml_Type.GetField("_refLevelCache", BindingFlags.NonPublic | BindingFlags.Instance)!;
		SignedXml_m_refLevelCache.SetValue(this, new int[references.Count]);
		//

		//ReferenceLevelSortOrder comparer = new ReferenceLevelSortOrder();
		var System_Security_Assembly = Assembly.Load("System.Security");
		var cripXmlAssembly = Assembly.Load("System.Security.Cryptography.Xml");
		Type ReferenceLevelSortOrder_Type = System_Security_Assembly.GetType("System.Security.Cryptography.Xml.SignedXml+ReferenceLevelSortOrder")!;
		ConstructorInfo ReferenceLevelSortOrder_Constructor = ReferenceLevelSortOrder_Type.GetConstructor(Array.Empty<Type>())!;
		object comparer = ReferenceLevelSortOrder_Constructor.Invoke(null);
		//

		//comparer.References = references;
		PropertyInfo ReferenceLevelSortOrder_References = ReferenceLevelSortOrder_Type.GetProperty("References", BindingFlags.Public | BindingFlags.Instance)!;
		ReferenceLevelSortOrder_References.SetValue(comparer, references, null);
		//

		var list2 = new ArrayList();
		foreach (Reference reference in references)
		{
			list2.Add(reference);
		}

		list2.Sort((IComparer)comparer);

		Type CanonicalXmlNodeList_Type = cripXmlAssembly.GetType("System.Security.Cryptography.Xml.CanonicalXmlNodeList")!;
		ConstructorInfo CanonicalXmlNodeList_Constructor = CanonicalXmlNodeList_Type.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, Array.Empty<Type>(), null)!;

		// refList is a list of elements that might be targets of references
		object refList = CanonicalXmlNodeList_Constructor.Invoke(null);

		MethodInfo CanonicalXmlNodeList_Add = CanonicalXmlNodeList_Type.GetMethod("Add", BindingFlags.Public | BindingFlags.Instance)!;

		//
		FieldInfo SignedXml_m_containingDocument = SignedXml_Type.GetField("_containingDocument", BindingFlags.NonPublic | BindingFlags.Instance)!;
		Type Reference_Type = typeof(Reference);
		MethodInfo Reference_UpdateHashValue = Reference_Type.GetMethod("UpdateHashValue", BindingFlags.NonPublic | BindingFlags.Instance)!;
		//

		object m_containingDocument = SignedXml_m_containingDocument.GetValue(this)!;

		if (ContentElement == null)
		{
			FindContentElement();
		}

		List<XmlAttribute> signatureParentNodeNameSpaces = GetAllNamespaces(GetSignatureElement());

		if (AddXadesNamespace)
		{
			XmlAttribute attr = _signatureDocument!.CreateAttribute("xmlns:xades");
			attr.Value = XadesNamespaceUri;

			signatureParentNodeNameSpaces.Add(attr);
		}

		foreach (Reference reference2 in list2)
		{
			XmlDocument? xmlDoc = null;
			bool addSignatureNamespaces = false;

			if (reference2.Uri.StartsWith("#KeyInfoId-"))
			{
				XmlElement keyInfoXml = KeyInfo.GetXml();
				SetPrefix(XmlDSigPrefix, keyInfoXml);

				xmlDoc = new XmlDocument();
				xmlDoc.LoadXml(keyInfoXml.OuterXml);

				addSignatureNamespaces = true;
			}
			else if (reference2.Type == SignedPropertiesType)
			{
				xmlDoc = (XmlDocument)_cachedXadesObjectDocument!.Clone();

				addSignatureNamespaces = true;
			}
			else if (reference2.Type == XmlDsigObjectType)
			{
				string dataObjectId = reference2.Uri.Substring(1);
				XmlElement? dataObjectXml = null;

				foreach (DataObject dataObject in m_signature.ObjectList)
				{
					if (dataObjectId == dataObject.Id)
					{
						dataObjectXml = dataObject.GetXml();

						SetPrefix(XmlDSigPrefix, dataObjectXml);

						addSignatureNamespaces = true;

						xmlDoc = new XmlDocument();
						xmlDoc.LoadXml(dataObjectXml.OuterXml);

						break;
					}
				}

				// If no DataObject found, search on document
				if (dataObjectXml == null)
				{
					dataObjectXml = GetIdElement(_signatureDocument!, dataObjectId);

					if (dataObjectXml != null)
					{
						xmlDoc = new XmlDocument
						{
							PreserveWhitespace = true,
						};
						xmlDoc.LoadXml(dataObjectXml.OuterXml);
					}
					else
					{
						throw new Exception("No reference target found");
					}
				}
			}
			else
			{
				xmlDoc = (XmlDocument)m_containingDocument;
			}


			if (addSignatureNamespaces)
			{
				foreach (XmlAttribute attr in signatureParentNodeNameSpaces)
				{
					XmlAttribute newAttr = xmlDoc!.CreateAttribute(attr.Name);
					newAttr.Value = attr.Value;

					xmlDoc.DocumentElement!.Attributes.Append(newAttr);
				}
			}

			if (xmlDoc != null)
			{
				CanonicalXmlNodeList_Add.Invoke(refList, new object?[] { xmlDoc.DocumentElement });
			}

			Reference_UpdateHashValue.Invoke(reference2, new object?[] { xmlDoc, refList });

			if (reference2.Id != null)
			{
				XmlElement xml = reference2.GetXml();

				SetPrefix(XmlDSigPrefix, xml);
			}
		}
	}

	private bool CheckDigestedReferences()
	{
		ArrayList references = m_signature.SignedInfo.References;

		var System_Security_Cryptography_Xml_Assembly = Assembly.Load("System.Security.Cryptography.Xml");
		Type CanonicalXmlNodeList_Type = System_Security_Cryptography_Xml_Assembly.GetType("System.Security.Cryptography.Xml.CanonicalXmlNodeList")!;
		ConstructorInfo CanonicalXmlNodeList_Constructor = CanonicalXmlNodeList_Type.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, Array.Empty<Type>(), null)!;

		MethodInfo CanonicalXmlNodeList_Add = CanonicalXmlNodeList_Type.GetMethod("Add", BindingFlags.Public | BindingFlags.Instance)!;
		object refList = CanonicalXmlNodeList_Constructor.Invoke(null);

		CanonicalXmlNodeList_Add.Invoke(refList, new object?[] { _signatureDocument });

		Type Reference_Type = typeof(Reference);
		MethodInfo Reference_CalculateHashValue = Reference_Type.GetMethod("CalculateHashValue", BindingFlags.NonPublic | BindingFlags.Instance)!;

		for (int i = 0; i < references.Count; ++i)
		{
			var digestedReference = (Reference)references[i]!;
			byte[] calculatedHash = (byte[])Reference_CalculateHashValue.Invoke(digestedReference, new object[] { _signatureDocument!, refList })!;

			if (calculatedHash.Length != digestedReference!.DigestValue.Length)
			{
				return false;
			}

			byte[] rgb1 = calculatedHash;
			byte[] rgb2 = digestedReference.DigestValue;
			for (int j = 0; j < rgb1.Length; ++j)
			{
				if (rgb1[j] != rgb2[j])
				{
					return false;
				}
			}
		}

		return true;
	}

	private bool CheckSignedInfo(AsymmetricAlgorithm key)
	{
		if (key == null)
		{
			throw new ArgumentNullException(nameof(key));
		}

		SignatureDescription signatureDescription = FirmaXadesNetCore.SignatureMethod
			.GetByUri(SignatureMethod)
			.Create();

		HashAlgorithm? hashAlgorithm = signatureDescription.CreateDigest();
		if (hashAlgorithm == null)
		{
			throw new CryptographicException("signature description can't be created");
		}

		// Necessary for correct calculation
		byte[] hashval = GetC14NDigest(hashAlgorithm, "ds");

		AsymmetricSignatureDeformatter asymmetricSignatureDeformatter = signatureDescription.CreateDeformatter(key);

		return asymmetricSignatureDeformatter.VerifySignature(hashval, m_signature.SignatureValue);
	}

	/// <summary>
	/// Copy of System.Security.Cryptography.Xml.SignedXml.GetC14NDigest() which will add a
	/// namespace prefix to all XmlDsig nodes
	/// </summary>
	private byte[] GetC14NDigest(HashAlgorithm hash, string prefix)
	{
		//if (!this.bCacheValid || !this.SignedInfo.CacheValid)
		//{
		Type SignedXml_Type = typeof(SignedXml);
		FieldInfo SignedXml_bCacheValid = SignedXml_Type.GetField("_bCacheValid", BindingFlags.NonPublic | BindingFlags.Instance)!;
		bool bCacheValid = (bool)SignedXml_bCacheValid.GetValue(this)!;
		Type SignedInfo_Type = typeof(SignedInfo);
		PropertyInfo SignedInfo_CacheValid = SignedInfo_Type.GetProperty("CacheValid", BindingFlags.NonPublic | BindingFlags.Instance)!;
		bool CacheValid = (bool)SignedInfo_CacheValid.GetValue(SignedInfo, null)!;

		FieldInfo SignedXml__digestedSignedInfo = SignedXml_Type.GetField("_digestedSignedInfo", BindingFlags.NonPublic | BindingFlags.Instance)!;

		if (!bCacheValid || !CacheValid)
		{
			//
			//string securityUrl = (this.m_containingDocument == null) ? null : this.m_containingDocument.BaseURI;
			FieldInfo SignedXml_m_containingDocument = SignedXml_Type.GetField("_containingDocument", BindingFlags.NonPublic | BindingFlags.Instance)!;
			var m_containingDocument = (XmlDocument?)SignedXml_m_containingDocument.GetValue(this);
			string? securityUrl = m_containingDocument?.BaseURI;
			//

			//XmlResolver xmlResolver = this.m_bResolverSet ? this.m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), securityUrl);
			FieldInfo SignedXml_m_bResolverSet = SignedXml_Type.GetField("_bResolverSet", BindingFlags.NonPublic | BindingFlags.Instance)!;
			bool m_bResolverSet = (bool)SignedXml_m_bResolverSet.GetValue(this)!;
			FieldInfo SignedXml_m_xmlResolver = SignedXml_Type.GetField("_xmlResolver", BindingFlags.NonPublic | BindingFlags.Instance)!;
			var m_xmlResolver = (XmlResolver)SignedXml_m_xmlResolver.GetValue(this)!;
			XmlResolver xmlResolver = m_bResolverSet ? m_xmlResolver : new XmlSecureResolver(new XmlUrlResolver(), securityUrl);
			//

			//XmlDocument document = Utils.PreProcessElementInput(this.SignedInfo.GetXml(), xmlResolver, securityUrl);
			var System_Security_Assembly = Assembly.Load("System.Security.Cryptography.Xml");
			Type Utils_Type = System_Security_Assembly.GetType("System.Security.Cryptography.Xml.Utils")!;
			MethodInfo Utils_PreProcessElementInput = Utils_Type.GetMethod("PreProcessElementInput", BindingFlags.NonPublic | BindingFlags.Static)!;

			XmlElement xml = SignedInfo.GetXml();
			SetPrefix(prefix, xml); // <---

			var document = (XmlDocument)Utils_PreProcessElementInput.Invoke(null, new object?[] { xml, xmlResolver, securityUrl })!;

			List<XmlAttribute> docNamespaces = GetAllNamespaces(GetSignatureElement());

			if (AddXadesNamespace)
			{
				XmlAttribute attr = _signatureDocument!.CreateAttribute("xmlns:xades");
				attr.Value = XadesNamespaceUri;

				docNamespaces.Add(attr);
			}


			foreach (XmlAttribute attr in docNamespaces)
			{
				XmlAttribute newAttr = document.CreateAttribute(attr.Name);
				newAttr.Value = attr.Value;

				document.DocumentElement!.Attributes.Append(newAttr);
			}

			//CanonicalXmlNodeList namespaces = (this.m_context == null) ? null : Utils.GetPropagatedAttributes(this.m_context);
			FieldInfo SignedXml_m_context = SignedXml_Type.GetField("_context", BindingFlags.NonPublic | BindingFlags.Instance)!;
			MethodInfo Utils_GetPropagatedAttributes = Utils_Type.GetMethod("GetPropagatedAttributes", BindingFlags.NonPublic | BindingFlags.Static)!;
			object m_context = SignedXml_m_context.GetValue(this)!;
			object? namespaces = (m_context == null) ? null : Utils_GetPropagatedAttributes.Invoke(null, new object[] { m_context });


			//

			// Utils.AddNamespaces(document.DocumentElement, namespaces);
			Type CanonicalXmlNodeList_Type = System_Security_Assembly.GetType("System.Security.Cryptography.Xml.CanonicalXmlNodeList")!;
			MethodInfo Utils_AddNamespaces = Utils_Type
				.GetMethod("AddNamespaces", BindingFlags.NonPublic | BindingFlags.Static, null, new Type[] { typeof(XmlElement), CanonicalXmlNodeList_Type }, null)!;
			Utils_AddNamespaces.Invoke(null, new object?[] { document.DocumentElement, namespaces });
			//

			//Transform canonicalizationMethodObject = this.SignedInfo.CanonicalizationMethodObject;
			System.Security.Cryptography.Xml.Transform canonicalizationMethodObject = SignedInfo.CanonicalizationMethodObject;
			//

			canonicalizationMethodObject.Resolver = xmlResolver;

			//canonicalizationMethodObject.BaseURI = securityUrl;
			Type Transform_Type = typeof(System.Security.Cryptography.Xml.Transform);
			PropertyInfo Transform_BaseURI = Transform_Type.GetProperty("BaseURI", BindingFlags.NonPublic | BindingFlags.Instance)!;
			Transform_BaseURI.SetValue(canonicalizationMethodObject, securityUrl, null);
			//

			canonicalizationMethodObject.LoadInput(document);

			//this._digestedSignedInfo = canonicalizationMethodObject.GetDigestedOutput(hash);
			SignedXml__digestedSignedInfo.SetValue(this, canonicalizationMethodObject.GetDigestedOutput(hash));
			//

			//this.bCacheValid = true;
			SignedXml_bCacheValid.SetValue(this, true);
			//
		}

		//return this._digestedSignedInfo;
		byte[] _digestedSignedInfo = (byte[])SignedXml__digestedSignedInfo.GetValue(this)!;

		return _digestedSignedInfo;
	}

	#endregion

	#region Private methods

	private static byte[] HashSha1(byte[] data)
	{
		if (data is null)
		{
			throw new ArgumentNullException(nameof(data));
		}

#if NET6_0_OR_GREATER
		return SHA1.HashData(data);
#else
		using var hashAlgorithm = SHA1.Create();

		return hashAlgorithm.ComputeHash(data);
#endif
	}

	private XmlElement? GetXadesObjectElement(XmlElement signatureElement)
	{
		var xmlNamespaceManager = new XmlNamespaceManager(signatureElement.OwnerDocument.NameTable); //Create an XmlNamespaceManager to resolve namespace
		xmlNamespaceManager.AddNamespace("ds", XmlDsigNamespaceUrl);
		xmlNamespaceManager.AddNamespace("xades", XadesNamespaceUri);

		XmlNodeList? xmlNodeList = signatureElement.SelectNodes("ds:Object/xades:QualifyingProperties", xmlNamespaceManager);

		XmlElement? result = xmlNodeList is not null
			&& xmlNodeList.Count > 0
				? (XmlElement?)xmlNodeList.Item(0)!.ParentNode
				: null;

		return result;
	}

	private void SetSignatureStandard(XmlElement signatureElement)
	{
		if (GetXadesObjectElement(signatureElement) != null)
		{
			SignatureStandard = KnownSignatureStandard.Xades;
		}
		else
		{
			SignatureStandard = KnownSignatureStandard.XmlDsig;
		}
	}

	private DataObject? GetXadesDataObject()
	{
		DataObject? result = null;

		for (int dataObjectCounter = 0; dataObjectCounter < Signature.ObjectList.Count; dataObjectCounter++)
		{
			var dataObject = (DataObject)Signature.ObjectList[dataObjectCounter]!;
			XmlElement dataObjectXmlElement = dataObject.GetXml();
			var xmlNamespaceManager = new XmlNamespaceManager(dataObjectXmlElement.OwnerDocument.NameTable);
			xmlNamespaceManager.AddNamespace("xades", XadesNamespaceUri);
			XmlNodeList? xmlNodeList = dataObjectXmlElement.SelectNodes("xades:QualifyingProperties", xmlNamespaceManager);

			if (xmlNodeList is not null
				&& xmlNodeList.Count != 0)
			{
				result = dataObject;
				break;
			}
		}

		return result;
	}

	private bool CheckHashDataInfosForTimeStamp(Timestamp timeStamp)
	{
		bool retVal = true;

		for (int referenceCounter = 0; retVal == true && (referenceCounter < SignedInfo.References.Count); referenceCounter++)
		{
			string referenceId = ((Reference)SignedInfo.References[referenceCounter]!).Id;
			string referenceUri = ((Reference)SignedInfo.References[referenceCounter]!).Uri;
			if (referenceUri != $"#{XadesObject.QualifyingProperties.SignedProperties.Id}")
			{
				bool hashDataInfoFound = false;
				for (int hashDataInfoCounter = 0; hashDataInfoFound == false && (hashDataInfoCounter < timeStamp.HashDataInfoCollection.Count); hashDataInfoCounter++)
				{
					HashDataInfo hashDataInfo = timeStamp.HashDataInfoCollection[hashDataInfoCounter];
					hashDataInfoFound = $"#{referenceId}" == hashDataInfo.UriAttribute;
				}
				retVal = hashDataInfoFound;
			}
		}

		return retVal;
	}

	private bool CheckHashDataInfosExist(Timestamp timeStamp)
	{
		bool retVal = true;

		for (int hashDataInfoCounter = 0; retVal == true && (hashDataInfoCounter < timeStamp.HashDataInfoCollection.Count); hashDataInfoCounter++)
		{
			HashDataInfo hashDataInfo = timeStamp.HashDataInfoCollection[hashDataInfoCounter];
			bool referenceFound = false;
			string referenceId;

			for (int referenceCounter = 0; referenceFound == false && (referenceCounter < SignedInfo.References.Count); referenceCounter++)
			{
				referenceId = ((Reference)SignedInfo.References[referenceCounter]!).Id;
				if ($"#{referenceId}" == hashDataInfo.UriAttribute)
				{
					referenceFound = true;
				}
			}
			retVal = referenceFound;
		}

		return retVal;
	}

	private bool CheckObjectReference(ObjectReference objectReference)
	{
		bool retVal = false;

		for (int referenceCounter = 0; retVal == false && (referenceCounter < SignedInfo.References.Count); referenceCounter++)
		{
			string referenceId = ((Reference)SignedInfo.References[referenceCounter]!).Id;
			if ($"#{referenceId}" == objectReference.ObjectReferenceUri)
			{
				retVal = true;
			}
		}

		return retVal;
	}

	private bool CheckHashDataInfoPointsToSignatureValue(Timestamp timeStamp)
	{
		bool result = true;

		foreach (HashDataInfo hashDataInfo in timeStamp.HashDataInfoCollection)
		{
			result &= hashDataInfo.UriAttribute == $"#{SignatureValueId}";
		}

		return result;
	}

	private bool CheckHashDataInfosOfSigAndRefsTimeStamp(Timestamp timeStamp)
	{
		UnsignedSignatureProperties unsignedSignatureProperties;
		bool signatureValueHashDataInfoFound = false;
		bool allSignatureTimeStampHashDataInfosFound = false;
		bool completeCertificateRefsHashDataInfoFound = false;
		bool completeRevocationRefsHashDataInfoFound = false;

		var signatureTimeStampIds = new ArrayList();

		unsignedSignatureProperties = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;

		foreach (Timestamp signatureTimeStamp in unsignedSignatureProperties.SignatureTimeStampCollection)
		{
			signatureTimeStampIds.Add($"#{signatureTimeStamp.EncapsulatedTimeStamp!.Id}");
		}
		signatureTimeStampIds.Sort();
		foreach (HashDataInfo hashDataInfo in timeStamp.HashDataInfoCollection)
		{
			if (hashDataInfo.UriAttribute == $"#{SignatureValueId}")
			{
				signatureValueHashDataInfoFound = true;
			}
			int signatureTimeStampIdIndex = signatureTimeStampIds.BinarySearch(hashDataInfo.UriAttribute);
			if (signatureTimeStampIdIndex >= 0)
			{
				signatureTimeStampIds.RemoveAt(signatureTimeStampIdIndex);
			}
			if (hashDataInfo.UriAttribute == $"#{unsignedSignatureProperties.CompleteCertificateRefs!.Id}")
			{
				completeCertificateRefsHashDataInfoFound = true;
			}
			if (hashDataInfo.UriAttribute == $"#{unsignedSignatureProperties.CompleteRevocationRefs!.Id}")
			{
				completeRevocationRefsHashDataInfoFound = true;
			}
		}
		if (signatureTimeStampIds.Count == 0)
		{
			allSignatureTimeStampHashDataInfosFound = true;
		}
		bool retVal = signatureValueHashDataInfoFound && allSignatureTimeStampHashDataInfosFound && completeCertificateRefsHashDataInfoFound && completeRevocationRefsHashDataInfoFound;
		return retVal;
	}

	private bool CheckHashDataInfosOfRefsOnlyTimeStamp(Timestamp timeStamp)
	{
		UnsignedSignatureProperties unsignedSignatureProperties;
		bool completeCertificateRefsHashDataInfoFound;
		bool completeRevocationRefsHashDataInfoFound;
		bool retVal;

		completeCertificateRefsHashDataInfoFound = false;
		completeRevocationRefsHashDataInfoFound = false;

		unsignedSignatureProperties = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
		foreach (HashDataInfo hashDataInfo in timeStamp.HashDataInfoCollection)
		{
			if (hashDataInfo.UriAttribute == "#" + unsignedSignatureProperties.CompleteCertificateRefs!.Id)
			{
				completeCertificateRefsHashDataInfoFound = true;
			}
			if (hashDataInfo.UriAttribute == "#" + unsignedSignatureProperties.CompleteRevocationRefs!.Id)
			{
				completeRevocationRefsHashDataInfoFound = true;
			}
		}
		retVal = completeCertificateRefsHashDataInfoFound && completeRevocationRefsHashDataInfoFound;

		return retVal;
	}

	private bool CheckHashDataInfosOfArchiveTimeStamp(Timestamp timeStamp)
	{
		if (timeStamp is null)
		{
			throw new ArgumentNullException(nameof(timeStamp));
		}

		UnsignedSignatureProperties unsignedSignatureProperties = XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties;
		SignedProperties signedProperties = XadesObject.QualifyingProperties.SignedProperties;

		var referenceIds = new ArrayList();
		foreach (Reference reference in Signature.SignedInfo.References)
		{
			if (reference.Uri != "#" + signedProperties.Id)
			{
				referenceIds.Add(reference.Uri);
			}
		}

		referenceIds.Sort();
		var signatureTimeStampIds = new ArrayList();
		foreach (Timestamp signatureTimeStamp in unsignedSignatureProperties.SignatureTimeStampCollection)
		{
			signatureTimeStampIds.Add("#" + signatureTimeStamp.EncapsulatedTimeStamp!.Id);
		}

		signatureTimeStampIds.Sort();
		var sigAndRefsTimeStampIds = new ArrayList();
		foreach (Timestamp sigAndRefsTimeStamp in unsignedSignatureProperties.SigAndRefsTimeStampCollection)
		{
			sigAndRefsTimeStampIds.Add("#" + sigAndRefsTimeStamp.EncapsulatedTimeStamp!.Id);
		}

		sigAndRefsTimeStampIds.Sort();
		var refsOnlyTimeStampIds = new ArrayList();
		foreach (Timestamp refsOnlyTimeStamp in unsignedSignatureProperties.RefsOnlyTimeStampCollection)
		{
			refsOnlyTimeStampIds.Add("#" + refsOnlyTimeStamp.EncapsulatedTimeStamp!.Id);
		}

		refsOnlyTimeStampIds.Sort();
		bool allOlderArchiveTimeStampsFound = false;
		var archiveTimeStampIds = new ArrayList();
		for (int archiveTimeStampCounter = 0;
			!allOlderArchiveTimeStampsFound && (archiveTimeStampCounter < unsignedSignatureProperties.ArchiveTimeStampCollection.Count);
			archiveTimeStampCounter++)
		{
			Timestamp archiveTimeStamp = unsignedSignatureProperties.ArchiveTimeStampCollection[archiveTimeStampCounter];
			if (archiveTimeStamp.EncapsulatedTimeStamp!.Id == timeStamp.EncapsulatedTimeStamp!.Id)
			{
				allOlderArchiveTimeStampsFound = true;
			}
			else
			{
				archiveTimeStampIds.Add("#" + archiveTimeStamp.EncapsulatedTimeStamp.Id);
			}
		}

		archiveTimeStampIds.Sort();

		bool signedInfoHashDataInfoFound = false;
		bool signedPropertiesHashDataInfoFound = false;
		bool signatureValueHashDataInfoFound = false;
		bool completeCertificateRefsHashDataInfoFound = false;
		bool completeRevocationRefsHashDataInfoFound = false;
		bool certificatesValuesHashDataInfoFound = false;
		bool revocationValuesHashDataInfoFound = false;

		foreach (HashDataInfo hashDataInfo in timeStamp.HashDataInfoCollection)
		{
			int index = referenceIds.BinarySearch(hashDataInfo.UriAttribute);
			if (index >= 0)
			{
				referenceIds.RemoveAt(index);
			}

			if (hashDataInfo.UriAttribute == $"#{_signedInfoIdBuffer}")
			{
				signedInfoHashDataInfoFound = true;
			}

			if (hashDataInfo.UriAttribute == $"#{signedProperties.Id}")
			{
				signedPropertiesHashDataInfoFound = true;
			}

			if (hashDataInfo.UriAttribute == $"#{SignatureValueId}")
			{
				signatureValueHashDataInfoFound = true;
			}

			index = signatureTimeStampIds.BinarySearch(hashDataInfo.UriAttribute);
			if (index >= 0)
			{
				signatureTimeStampIds.RemoveAt(index);
			}

			if (hashDataInfo.UriAttribute == $"#{unsignedSignatureProperties.CompleteCertificateRefs!.Id}")
			{
				completeCertificateRefsHashDataInfoFound = true;
			}

			if (hashDataInfo.UriAttribute == $"#{unsignedSignatureProperties.CompleteRevocationRefs!.Id}")
			{
				completeRevocationRefsHashDataInfoFound = true;
			}

			if (hashDataInfo.UriAttribute == $"#{unsignedSignatureProperties.CertificateValues!.Id}")
			{
				certificatesValuesHashDataInfoFound = true;
			}

			if (hashDataInfo.UriAttribute == $"#{unsignedSignatureProperties.RevocationValues!.Id}")
			{
				revocationValuesHashDataInfoFound = true;
			}

			index = sigAndRefsTimeStampIds.BinarySearch(hashDataInfo.UriAttribute);
			if (index >= 0)
			{
				sigAndRefsTimeStampIds.RemoveAt(index);
			}

			index = refsOnlyTimeStampIds.BinarySearch(hashDataInfo.UriAttribute);
			if (index >= 0)
			{
				refsOnlyTimeStampIds.RemoveAt(index);
			}

			index = archiveTimeStampIds.BinarySearch(hashDataInfo.UriAttribute);
			if (index >= 0)
			{
				archiveTimeStampIds.RemoveAt(index);
			}
		}


		bool allReferenceHashDataInfosFound = false;
		if (referenceIds.Count == 0)
		{
			allReferenceHashDataInfosFound = true;
		}


		bool allSignatureTimeStampHashDataInfosFound = false;
		if (signatureTimeStampIds.Count == 0)
		{
			allSignatureTimeStampHashDataInfosFound = true;
		}


		bool allSigAndRefsTimeStampHashDataInfosFound = false;
		if (sigAndRefsTimeStampIds.Count == 0)
		{
			allSigAndRefsTimeStampHashDataInfosFound = true;
		}


		bool allRefsOnlyTimeStampHashDataInfosFound = false;
		if (refsOnlyTimeStampIds.Count == 0)
		{
			allRefsOnlyTimeStampHashDataInfosFound = true;
		}


		bool allArchiveTimeStampHashDataInfosFound = false;
		if (archiveTimeStampIds.Count == 0)
		{
			allArchiveTimeStampHashDataInfosFound = true;
		}

		bool result = allReferenceHashDataInfosFound
			&& signedInfoHashDataInfoFound
			&& signedPropertiesHashDataInfoFound
			&& signatureValueHashDataInfoFound
			&& allSignatureTimeStampHashDataInfosFound
			&& completeCertificateRefsHashDataInfoFound
			&& completeRevocationRefsHashDataInfoFound
			&& certificatesValuesHashDataInfoFound
			&& revocationValuesHashDataInfoFound
			&& allSigAndRefsTimeStampHashDataInfosFound
			&& allRefsOnlyTimeStampHashDataInfosFound
			&& allArchiveTimeStampHashDataInfosFound;

		return result;
	}

	#endregion
}
