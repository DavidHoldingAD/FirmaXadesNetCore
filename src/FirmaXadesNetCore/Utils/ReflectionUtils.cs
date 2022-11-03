using System.Collections;
using System.Reflection;
using System.Security.Cryptography.Xml;
using System.Xml;
using System.Xml.Schema;

namespace FirmaXadesNetCore.Utils;

internal static class ReflectionUtils
{
	private const string XadesXSDResourceName = "FirmaXadesNetCore.Utils.XAdES.xsd";
	private const string XmlDsigCoreXsdResourceName = "FirmaXadesNetCore.Utils.xmldsig-core-schema.xsd";

#if NET6_0_OR_GREATER
	private const string SignedXmlRefProcessedFieldName = "_refProcessed";
	private const string SignedXmlRefLevelCacheFieldName = "_refLevelCache";
	private const string SignedXmlContainingDocumentFieldName = "_containingDocument";
	private const string SignedXmlBCacheValidFieldName = "_bCacheValid";
	private const string SignedXmlBResolverSetFieldName = "_bResolverSet";
	private const string SignedXmlXmlResolverFieldName = "_xmlResolver";
	private const string SignedXmlContextFieldName = "_context";
	private const string SystemSecurityAssemblyFullName = "System.Security";
#else
	private const string SignedXmlRefProcessedFieldName = "m_refProcessed";
	private const string SignedXmlRefLevelCacheFieldName = "m_refLevelCache";
	private const string SignedXmlContainingDocumentFieldName = "m_containingDocument";
	private const string SignedXmlBCacheValidFieldName = "bCacheValid";
	private const string SignedXmlBResolverSetFieldName = "m_bResolverSet";
	private const string SignedXmlXmlResolverFieldName = "m_xmlResolver";
	private const string SignedXmlContextFieldName = "m_context";
	private const string SystemSecurityAssemblyFullName = "System.Security, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a";
#endif

	private static readonly Type _signedXmlType = typeof(SignedXml);
	private static readonly Type _signedInfoType = typeof(SignedInfo);
	private static readonly Type _referenceType = typeof(Reference);
	private static readonly Type _transformType = typeof(Transform);
	private static readonly Type _xmlDsigXPathTransformType = typeof(XmlDsigXPathTransform);
	private static readonly Type _ocspReqGeneratorInfoType = typeof(Org.BouncyCastle.Ocsp.OcspReqGenerator);

	private static readonly FieldInfo _signedXmlRefProcessed = _signedXmlType
		.GetField(SignedXmlRefProcessedFieldName, BindingFlags.NonPublic | BindingFlags.Instance)!;
	private static readonly FieldInfo _signedXmlLevelCache = _signedXmlType
		.GetField(SignedXmlRefLevelCacheFieldName, BindingFlags.NonPublic | BindingFlags.Instance)!;
	private static readonly FieldInfo _signedXmlContainingDocument = _signedXmlType
		.GetField(SignedXmlContainingDocumentFieldName, BindingFlags.NonPublic | BindingFlags.Instance)!;
	private static readonly FieldInfo _signedXmlBCacheValid = _signedXmlType
		.GetField(SignedXmlBCacheValidFieldName, BindingFlags.NonPublic | BindingFlags.Instance)!;
	private static readonly FieldInfo _signedXmlBResolverSet = _signedXmlType
		.GetField(SignedXmlBResolverSetFieldName, BindingFlags.NonPublic | BindingFlags.Instance)!;
	private static readonly FieldInfo _signedXmlXmlResolver = _signedXmlType
		.GetField(SignedXmlXmlResolverFieldName, BindingFlags.NonPublic | BindingFlags.Instance)!;
	private static readonly FieldInfo _signedXmlContext = _signedXmlType
		.GetField(SignedXmlContextFieldName, BindingFlags.NonPublic | BindingFlags.Instance)!;
	private static readonly FieldInfo _signedXmlDigestedSignedInfo = _signedXmlType
		.GetField("_digestedSignedInfo", BindingFlags.NonPublic | BindingFlags.Instance)!;

	private static readonly PropertyInfo _signedInfoTypeCacheValid = _signedInfoType
		.GetProperty("CacheValid", BindingFlags.NonPublic | BindingFlags.Instance)!;

	private static readonly Assembly _systemSecurityAssembly = Assembly.Load(SystemSecurityAssemblyFullName);
	private static readonly Type _referenceLevelSortOrderType = _systemSecurityAssembly
		.GetType("System.Security.Cryptography.Xml.SignedXml+ReferenceLevelSortOrder")!;
	private static readonly ConstructorInfo _referenceLevelSortOrderConstructorInfo = _referenceLevelSortOrderType
		.GetConstructor(Array.Empty<Type>())!;
	private static readonly PropertyInfo _referenceLevelSortOrderReferences = _referenceLevelSortOrderType
		.GetProperty("References", BindingFlags.Public | BindingFlags.Instance)!;

#if NET6_0_OR_GREATER
	private static readonly Assembly _cripXmlAssembly = Assembly.Load("System.Security.Cryptography.Xml");
#else
	private static readonly Assembly _cripXmlAssembly = _systemSecurityAssembly;
#endif

	private static readonly Type _canonicalXmlNodeListType = _cripXmlAssembly
		.GetType("System.Security.Cryptography.Xml.CanonicalXmlNodeList")!;
	private static readonly ConstructorInfo _canonicalXmlNodeListConstructorInfo = _canonicalXmlNodeListType
		.GetConstructor(BindingFlags.NonPublic | BindingFlags.Instance, null, Array.Empty<Type>(), null)!;
	private static readonly MethodInfo _canonicalXmlNodeListAddMethod = _canonicalXmlNodeListType
		.GetMethod("Add", BindingFlags.Public | BindingFlags.Instance)!;

	private static readonly MethodInfo _referenceUpdateHashValueMethod = _referenceType
		.GetMethod("UpdateHashValue", BindingFlags.NonPublic | BindingFlags.Instance)!;
	private static readonly MethodInfo _referenceCalculateHashValueMethod = _referenceType
		.GetMethod("CalculateHashValue", BindingFlags.NonPublic | BindingFlags.Instance)!;

	private static readonly Type _xmlUtilsType = _cripXmlAssembly
		.GetType("System.Security.Cryptography.Xml.Utils")!;
	private static readonly MethodInfo _xmlUtilsPreProcessElementInputMethod = _xmlUtilsType
		.GetMethod("PreProcessElementInput", BindingFlags.NonPublic | BindingFlags.Static)!;
	private static readonly MethodInfo _xmlUtilsGetPropagatedAttributes = _xmlUtilsType
		.GetMethod("GetPropagatedAttributes", BindingFlags.NonPublic | BindingFlags.Static)!;
	private static readonly MethodInfo _xmlUtilsAddNamespaces = _xmlUtilsType
		.GetMethod("AddNamespaces", BindingFlags.NonPublic | BindingFlags.Static, null,
			new Type[] { typeof(XmlElement), _canonicalXmlNodeListType }, null)!;

	private static readonly PropertyInfo _transformBaseURI = _transformType
		.GetProperty("BaseURI", BindingFlags.NonPublic | BindingFlags.Instance)!;

	private static readonly FieldInfo _xmlDsigXPathTransformNsm = _xmlDsigXPathTransformType
		.GetField("_nsm", BindingFlags.NonPublic | BindingFlags.Instance)!;

	private static readonly FieldInfo _ocspReqGeneratorInfoList = _ocspReqGeneratorInfoType
		.GetField("list", BindingFlags.NonPublic | BindingFlags.Instance)!;
	private static readonly Type _ocspReqGeneratorInfoRequestObjectType = _ocspReqGeneratorInfoType
		.GetNestedType("RequestObject", BindingFlags.NonPublic | BindingFlags.Instance)!;
	private static readonly MethodInfo _ocspReqGeneratorInfoRequestToRequestMethod = _ocspReqGeneratorInfoRequestObjectType
		.GetMethod("ToRequest")!;
	private static readonly FieldInfo _ocspReqGeneratorInfoRequestorName = _ocspReqGeneratorInfoType
		.GetField("requestorName", BindingFlags.NonPublic | BindingFlags.Instance)!;
	private static readonly FieldInfo _ocspReqGeneratorInfoRequestExtensions = _ocspReqGeneratorInfoType
		.GetField("requestExtensions", BindingFlags.NonPublic | BindingFlags.Instance)!;

	public static XmlSchemaSet CreateXadesSchemaSet()
	{
		Assembly assembly = typeof(ReflectionUtils).Assembly;

		var schemaSet = new XmlSchemaSet
		{
			XmlResolver = null,
		};

		var xmlReaderSettings = new XmlReaderSettings
		{
			XmlResolver = null,
		};

		using (Stream stream = assembly.GetManifestResourceStream(XmlDsigCoreXsdResourceName)!)
		using (var xmlReader = XmlReader.Create(stream, xmlReaderSettings))
		{
			schemaSet.Add(null, xmlReader);
		}

		using (Stream stream = assembly.GetManifestResourceStream(XadesXSDResourceName)!)
		using (var xmlReader = XmlReader.Create(stream, xmlReaderSettings))
		{
			schemaSet.Add(null, xmlReader);
		}

		return schemaSet;
	}

	public static void SetSignedXmlRefProcessed(SignedXml signedXml, bool[] value)
	{
		if (signedXml is null)
		{
			throw new ArgumentNullException(nameof(signedXml));
		}

		if (value is null)
		{
			throw new ArgumentNullException(nameof(value));
		}

		_signedXmlRefProcessed.SetValue(signedXml, value);
	}

	public static void SetSignedXmlRefLevelCache(SignedXml signedXml, int[] value)
	{
		if (signedXml is null)
		{
			throw new ArgumentNullException(nameof(signedXml));
		}

		if (value is null)
		{
			throw new ArgumentNullException(nameof(value));
		}

		_signedXmlLevelCache.SetValue(signedXml, value);
	}

	public static XmlDocument? GetSignedXmlContainingDocument(SignedXml signedXml)
	{
		if (signedXml is null)
		{
			throw new ArgumentNullException(nameof(signedXml));
		}

		var result = (XmlDocument?)_signedXmlContainingDocument.GetValue(signedXml);

		return result;
	}

	public static bool GetSignedXmlBCacheValid(SignedXml signedXml)
	{
		if (signedXml is null)
		{
			throw new ArgumentNullException(nameof(signedXml));
		}

		bool result = (bool)_signedXmlBCacheValid.GetValue(signedXml)!;

		return result;
	}

	public static void SetSignedXmlBCacheValid(SignedXml signedXml, bool value)
	{
		if (signedXml is null)
		{
			throw new ArgumentNullException(nameof(signedXml));
		}

		_signedXmlBCacheValid.SetValue(signedXml, value);
	}

	public static bool GetSignedXmlBResolverSet(SignedXml signedXml)
	{
		if (signedXml is null)
		{
			throw new ArgumentNullException(nameof(signedXml));
		}

		bool result = (bool)_signedXmlBResolverSet.GetValue(signedXml)!;

		return result;
	}

	public static XmlResolver GetSignedXmlXmlResolver(SignedXml signedXml)
	{
		if (signedXml is null)
		{
			throw new ArgumentNullException(nameof(signedXml));
		}

		var result = (XmlResolver)_signedXmlXmlResolver.GetValue(signedXml)!;

		return result;
	}

	public static XmlElement? GetSignedXmlContext(SignedXml signedXml)
	{
		if (signedXml is null)
		{
			throw new ArgumentNullException(nameof(signedXml));
		}

		var result = (XmlElement?)_signedXmlContext.GetValue(signedXml);

		return result;
	}

	public static byte[] GetSignedXmlDigestedSignedInfo(SignedXml signedXml)
	{
		if (signedXml is null)
		{
			throw new ArgumentNullException(nameof(signedXml));
		}

		byte[] result = (byte[])_signedXmlDigestedSignedInfo.GetValue(signedXml)!;

		return result;
	}

	public static void SetSignedXmlDigestedSignedInfo(SignedXml signedXml, byte[] value)
	{
		if (signedXml is null)
		{
			throw new ArgumentNullException(nameof(signedXml));
		}

		if (value is null)
		{
			throw new ArgumentNullException(nameof(value));
		}

		_signedXmlDigestedSignedInfo.SetValue(signedXml, value);
	}

	public static bool GetSignedInfoCacheValid(SignedInfo signedInfo)
	{
		if (signedInfo is null)
		{
			throw new ArgumentNullException(nameof(signedInfo));
		}

		bool result = (bool)_signedInfoTypeCacheValid.GetValue(signedInfo)!;

		return result;
	}

	public static IComparer CreateSignedXmlReferenceLevelSortOrder()
	{
		var result = (IComparer)_referenceLevelSortOrderConstructorInfo.Invoke(null);

		return result;
	}

	public static void SetSignedXmlReferenceLevelSortOrderReferences(IComparer comparer, ArrayList value)
	{
		if (comparer is null)
		{
			throw new ArgumentNullException(nameof(comparer));
		}

		if (value is null)
		{
			throw new ArgumentNullException(nameof(value));
		}

		_referenceLevelSortOrderReferences.SetValue(comparer, value, null);
	}

	public static XmlNodeList CreateCanonicalXmlNodeList()
	{
		var result = (XmlNodeList)_canonicalXmlNodeListConstructorInfo.Invoke(null);

		return result;
	}

	public static void AddToCanonicalXmlNodeList(XmlNodeList list, XmlNode? value)
	{
		if (list is null)
		{
			throw new ArgumentNullException(nameof(list));
		}

		_canonicalXmlNodeListAddMethod.Invoke(list, new object?[] { value });
	}

	public static void UpdateReferenceHashValue(Reference reference, XmlDocument? xmlDocument, XmlNodeList nodeList)
	{
		if (reference is null)
		{
			throw new ArgumentNullException(nameof(reference));
		}

		if (nodeList is null)
		{
			throw new ArgumentNullException(nameof(nodeList));
		}

		_referenceUpdateHashValueMethod.Invoke(reference, new object?[] { xmlDocument, nodeList });
	}

	public static byte[] CalculateReferenceHashValue(Reference reference, XmlDocument? xmlDocument, XmlNodeList nodeList)
	{
		if (reference is null)
		{
			throw new ArgumentNullException(nameof(reference));
		}

		if (nodeList is null)
		{
			throw new ArgumentNullException(nameof(nodeList));
		}

		byte[] result = (byte[])_referenceCalculateHashValueMethod.Invoke(reference, new object?[] { xmlDocument, nodeList })!;

		return result;
	}

	public static XmlDocument XmlUtilsPreProcessElementInput(XmlElement? xmlElement, XmlResolver? xmlResolver, string? securityUrl)
	{
		var result = (XmlDocument)_xmlUtilsPreProcessElementInputMethod.Invoke(null, new object?[] { xmlElement, xmlResolver, securityUrl })!;

		return result;
	}

	public static XmlNodeList? XmlUtilsGetPropagatedAttributes(XmlElement? xmlElement)
	{
		var result = (XmlNodeList?)_xmlUtilsGetPropagatedAttributes.Invoke(null, new object?[] { xmlElement });

		return result;
	}

	public static void XmlUtilsAddNamespaces(XmlElement? xmlElement, XmlNodeList? namespaces)
		=> _xmlUtilsAddNamespaces.Invoke(null, new object?[] { xmlElement, namespaces });

	public static void SetTransformBaseURI(Transform transform, string? securityUrl)
	{
		if (transform is null)
		{
			throw new ArgumentNullException(nameof(transform));
		}

		_transformBaseURI.SetValue(transform, securityUrl, null);
	}

	public static XmlNamespaceManager GetXmlDsigXPathTransformNamespaceManager(XmlDsigXPathTransform transform)
	{
		if (transform is null)
		{
			throw new ArgumentNullException(nameof(transform));
		}

		var result = (XmlNamespaceManager)_xmlDsigXPathTransformNsm.GetValue(transform)!;

		return result;
	}

	public static IList GetOcspReqGeneratorList(Org.BouncyCastle.Ocsp.OcspReqGenerator generator)
	{
		if (generator is null)
		{
			throw new ArgumentNullException(nameof(generator));
		}

		var result = (IList)_ocspReqGeneratorInfoList.GetValue(generator)!;

		return result;
	}

	public static Org.BouncyCastle.Asn1.Ocsp.Request OcspReqGeneratorInfoRequestToRequest(object reqObj)
	{
		if (reqObj is null)
		{
			throw new ArgumentNullException(nameof(reqObj));
		}

		var result = (Org.BouncyCastle.Asn1.Ocsp.Request)_ocspReqGeneratorInfoRequestToRequestMethod.Invoke(reqObj, null)!;

		return result;
	}

	public static Org.BouncyCastle.Asn1.X509.GeneralName GetOcspReqGeneratorInfoRequestorName(Org.BouncyCastle.Ocsp.OcspReqGenerator generator)
	{
		if (generator is null)
		{
			throw new ArgumentNullException(nameof(generator));
		}

		var result = (Org.BouncyCastle.Asn1.X509.GeneralName)_ocspReqGeneratorInfoRequestorName.GetValue(generator)!;

		return result;
	}

	public static Org.BouncyCastle.Asn1.X509.X509Extensions GetOcspReqGeneratorInfoRequestExtensions(Org.BouncyCastle.Ocsp.OcspReqGenerator generator)
	{
		if (generator is null)
		{
			throw new ArgumentNullException(nameof(generator));
		}

		var result = (Org.BouncyCastle.Asn1.X509.X509Extensions)_ocspReqGeneratorInfoRequestExtensions.GetValue(generator)!;

		return result;
	}
}
