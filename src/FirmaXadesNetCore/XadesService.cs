// --------------------------------------------------------------------------------------------------------------------
// XadesService.cs
//
// FirmaXadesNet - Librería para la generación de firmas XADES
// Copyright (C) 2016 Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
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
//
// E-Mail: informatica@gemuc.es
// 
// --------------------------------------------------------------------------------------------------------------------

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;
using FirmaXadesNetCore.Signature;
using FirmaXadesNetCore.Signature.Parameters;
using FirmaXadesNetCore.Utils;
using FirmaXadesNetCore.Validation;
using Microsoft.Xades;

namespace FirmaXadesNetCore;

/// <summary>
/// Represents a XAdES signing service.
/// </summary>
public class XadesService : IXadesService
{
	private Reference _refContent;
	private DataObjectFormat _dataFormat;

	#region IXadesService Members

	/// <inheritdoc/>
	public SignatureDocument Sign(Stream stream, LocalSignatureParameters parameters)
	{
		if (parameters is null)
		{
			throw new ArgumentNullException(nameof(parameters));
		}

		if (parameters.Signer is null)
		{
			throw new Exception("A valid certificate is required for signing.");
		}

		if (stream is null
			&& string.IsNullOrEmpty(parameters.ExternalContentUri))
		{
			throw new Exception("No content to sign has been specified.");
		}

		var signatureDocument = new SignatureDocument();
		_dataFormat = new DataObjectFormat();

		switch (parameters.SignaturePackaging)
		{
			case SignaturePackaging.INTERNALLY_DETACHED:
				if (parameters.DataFormat == null || string.IsNullOrEmpty(parameters.DataFormat.MimeType))
				{
					throw new NullReferenceException("You need to specify the MIME type of the element to sign.");
				}

				_dataFormat.MimeType = parameters.DataFormat.MimeType;

				if (parameters.DataFormat.MimeType == "text/xml")
				{
					_dataFormat.Encoding = "UTF-8";
				}
				else
				{
					_dataFormat.Encoding = "http://www.w3.org/2000/09/xmldsig#base64";
				}

				if (!string.IsNullOrEmpty(parameters.ElementIdToSign))
				{
					SetContentInternallyDetached(signatureDocument, XmlUtils.LoadDocument(stream), parameters.ElementIdToSign);
				}
				else
				{
					SetContentInternallyDetached(signatureDocument, stream);
				}
				break;

			case SignaturePackaging.HASH_INTERNALLY_DETACHED:
				if (parameters.DataFormat == null || string.IsNullOrEmpty(parameters.DataFormat.MimeType))
				{
					_dataFormat.MimeType = "application/octet-stream";
				}
				else
				{
					_dataFormat.MimeType = parameters.DataFormat.MimeType;
				}
				_dataFormat.Encoding = "http://www.w3.org/2000/09/xmldsig#base64";
				SetContentInternallyDetachedHashed(signatureDocument, stream);
				break;

			case SignaturePackaging.ENVELOPED:
				_dataFormat.MimeType = "text/xml";
				_dataFormat.Encoding = "UTF-8";
				SetContentEnveloped(signatureDocument, XmlUtils.LoadDocument(stream));
				break;

			case SignaturePackaging.ENVELOPING:
				_dataFormat.MimeType = "text/xml";
				_dataFormat.Encoding = "UTF-8";
				SetContentEveloping(signatureDocument, XmlUtils.LoadDocument(stream));
				break;

			case SignaturePackaging.EXTERNALLY_DETACHED:
				SetContentExternallyDetached(signatureDocument, parameters.ExternalContentUri);
				break;
		}

		if (parameters.DataFormat != null)
		{
			if (!string.IsNullOrEmpty(parameters.DataFormat.TypeIdentifier))
			{
				_dataFormat.ObjectIdentifier = new ObjectIdentifier();
				_dataFormat.ObjectIdentifier.Identifier.IdentifierUri = parameters.DataFormat.TypeIdentifier;
			}

			_dataFormat.Description = parameters.DataFormat.Description;
		}

		SetSignatureId(signatureDocument.XadesSignature);

		PrepareSignature(signatureDocument, parameters);

		signatureDocument.XadesSignature.ComputeSignature();

		UpdateXadesSignature(signatureDocument);

		return signatureDocument;
	}

	/// <inheritdoc/>
	public SignatureDocument CoSign(SignatureDocument signatureDocument, LocalSignatureParameters parameters)
	{
		if (signatureDocument is null)
		{
			throw new ArgumentNullException(nameof(signatureDocument));
		}

		if (parameters is null)
		{
			throw new ArgumentNullException(nameof(parameters));
		}

		SignatureDocument.CheckSignatureDocument(signatureDocument);

		_refContent = signatureDocument.XadesSignature.GetContentReference();
		if (_refContent is null)
		{
			throw new Exception("The signed content reference could not be found.");
		}

		_dataFormat = null;

		foreach (DataObjectFormat dof in signatureDocument.XadesSignature.XadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties.DataObjectFormatCollection)
		{
			if (dof.ObjectReferenceAttribute == ("#" + _refContent.Id))
			{
				_dataFormat = new DataObjectFormat
				{
					Encoding = dof.Encoding,
					MimeType = dof.MimeType,
					Description = dof.Description
				};

				if (dof.ObjectIdentifier != null)
				{
					_dataFormat.ObjectIdentifier = new ObjectIdentifier();
					_dataFormat.ObjectIdentifier.Identifier.IdentifierUri = dof.ObjectIdentifier.Identifier.IdentifierUri;
					_dataFormat.ObjectIdentifier.Description = dof.ObjectIdentifier.Description;
				}

				break;
			}
		}

		var coSignatureDocument = new SignatureDocument
		{
			Document = (XmlDocument)signatureDocument.Document.Clone()
		};
		coSignatureDocument.Document.PreserveWhitespace = true;

		coSignatureDocument.XadesSignature = new XadesSignedXml(coSignatureDocument.Document);
		coSignatureDocument.XadesSignature.LoadXml(signatureDocument.XadesSignature.GetXml());

		XmlNode destination = coSignatureDocument.XadesSignature.GetSignatureElement().ParentNode;

		coSignatureDocument.XadesSignature = new XadesSignedXml(coSignatureDocument.Document);

		_refContent.Id = "Reference-" + Guid.NewGuid().ToString();

		if (_refContent.Type != XadesSignedXml.XmlDsigObjectType)
		{
			_refContent.Type = "";
		}

		coSignatureDocument.XadesSignature.AddReference(_refContent);

		if (destination.NodeType != XmlNodeType.Document)
		{
			coSignatureDocument.XadesSignature.SignatureNodeDestination = (XmlElement)destination;
		}
		else
		{
			coSignatureDocument.XadesSignature.SignatureNodeDestination = ((XmlDocument)destination).DocumentElement;
		}


		SetSignatureId(coSignatureDocument.XadesSignature);

		PrepareSignature(coSignatureDocument, parameters);

		coSignatureDocument.XadesSignature.ComputeSignature();

		UpdateXadesSignature(coSignatureDocument);

		return coSignatureDocument;
	}

	/// <inheritdoc/>
	public SignatureDocument CounterSign(SignatureDocument signatureDocument, LocalSignatureParameters parameters)
	{
		if (parameters.Signer == null)
		{
			throw new Exception("A valid certificate is required for signing.");
		}

		SignatureDocument.CheckSignatureDocument(signatureDocument);

		var counterSigDocument = new SignatureDocument
		{
			Document = (XmlDocument)signatureDocument.Document.Clone()
		};
		counterSigDocument.Document.PreserveWhitespace = true;

		var counterSignature = new XadesSignedXml(counterSigDocument.Document);
		SetSignatureId(counterSignature);

		counterSignature.SigningKey = parameters.Signer.Certificate.GetRSAPrivateKey();

		_refContent = new Reference
		{
			Uri = "#" + signatureDocument.XadesSignature.SignatureValueId,
			Id = "Reference-" + Guid.NewGuid().ToString(),
			Type = "http://uri.etsi.org/01903#CountersignedSignature"
		};
		_refContent.AddTransform(new XmlDsigC14NTransform());
		counterSignature.AddReference(_refContent);

		_dataFormat = new DataObjectFormat
		{
			MimeType = "text/xml",
			Encoding = "UTF-8"
		};

		var keyInfo = new KeyInfo
		{
			Id = "KeyInfoId-" + counterSignature.Signature.Id
		};
		keyInfo.AddClause(new KeyInfoX509Data(parameters.Signer.Certificate));
		keyInfo.AddClause(new RSAKeyValue((RSA)counterSignature.SigningKey));
		counterSignature.KeyInfo = keyInfo;

		var referenceKeyInfo = new Reference
		{
			Id = "ReferenceKeyInfo-" + counterSignature.Signature.Id,
			Uri = "#KeyInfoId-" + counterSignature.Signature.Id
		};
		counterSignature.AddReference(referenceKeyInfo);

		var counterSignatureXadesObject = new XadesObject
		{
			Id = "CounterSignatureXadesObject-" + Guid.NewGuid().ToString()
		};
		counterSignatureXadesObject.QualifyingProperties.Target = "#" + counterSignature.Signature.Id;
		counterSignatureXadesObject.QualifyingProperties.SignedProperties.Id = "SignedProperties-" + counterSignature.Signature.Id;

		AddSignatureProperties(counterSigDocument,
			counterSignatureXadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties,
			counterSignatureXadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties,
			parameters,
			parameters.Signer.Certificate);

		counterSignature.AddXadesObject(counterSignatureXadesObject);

		foreach (Reference signReference in counterSignature.SignedInfo.References)
		{
			signReference.DigestMethod = parameters.DigestMethod.Uri;
		}

		counterSignature.SignedInfo.SignatureMethod = parameters.SignatureMethod.URI;

		counterSignature.AddXadesNamespace = true;
		counterSignature.ComputeSignature();

		UnsignedProperties unsignedProperties = signatureDocument.XadesSignature.UnsignedProperties;
		unsignedProperties.UnsignedSignatureProperties.CounterSignatureCollection.Add(counterSignature);
		signatureDocument.XadesSignature.UnsignedProperties = unsignedProperties;

		UpdateXadesSignature(signatureDocument);

		counterSigDocument.Document = (XmlDocument)signatureDocument.Document.Clone();
		counterSigDocument.Document.PreserveWhitespace = true;

		var signatureElement = (XmlElement)signatureDocument.Document.SelectSingleNode("//*[@Id='" + counterSignature.Signature.Id + "']");

		counterSigDocument.XadesSignature = new XadesSignedXml(counterSigDocument.Document);
		counterSigDocument.XadesSignature.LoadXml(signatureElement);

		return counterSigDocument;
	}

	/// <inheritdoc/>
	public SignatureDocument GetRemotingSigningDigest(XmlDocument xmlDocument, RemoteSignatureParameters parameters, out byte[] digest)
	{
		if (xmlDocument is null)
		{
			throw new ArgumentNullException(nameof(xmlDocument));
		}

		if (parameters is null)
		{
			throw new ArgumentNullException(nameof(parameters));
		}

		if (parameters.PublicCertificate is null)
		{
			throw new ArgumentException($"Public certificate is required.", nameof(parameters));
		}

		if (parameters.PublicCertificate.HasPrivateKey)
		{
			throw new ArgumentException($"Public certificate should contain only public key.", nameof(parameters));
		}

		var signatureDocument = new SignatureDocument();
		_dataFormat = new DataObjectFormat();

		switch (parameters.SignaturePackaging)
		{
			case SignaturePackaging.INTERNALLY_DETACHED:
				{
					if (parameters.DataFormat == null || string.IsNullOrEmpty(parameters.DataFormat.MimeType))
					{
						throw new NullReferenceException("You need to specify the MIME type of the element to sign.");
					}

					_dataFormat.MimeType = parameters.DataFormat.MimeType;

					if (parameters.DataFormat.MimeType == "text/xml")
					{
						_dataFormat.Encoding = "UTF-8";
					}
					else
					{
						_dataFormat.Encoding = "http://www.w3.org/2000/09/xmldsig#base64";
					}

					if (string.IsNullOrEmpty(parameters.ElementIdToSign))
					{
						throw new ArgumentException(
							$"Element id to sign is required for `{parameters.SignaturePackaging}` signature packaging.",
							nameof(parameters));
					}

					SetContentInternallyDetached(signatureDocument, xmlDocument, parameters.ElementIdToSign);
					break;
				}
			case SignaturePackaging.ENVELOPED:
				{
					_dataFormat.MimeType = "text/xml";
					_dataFormat.Encoding = "UTF-8";

					SetContentEnveloped(signatureDocument, xmlDocument);
					break;
				}
			case SignaturePackaging.ENVELOPING:
				{
					_dataFormat.MimeType = "text/xml";
					_dataFormat.Encoding = "UTF-8";

					SetContentEveloping(signatureDocument, xmlDocument);
					break;
				}
			case SignaturePackaging.HASH_INTERNALLY_DETACHED:
			case SignaturePackaging.EXTERNALLY_DETACHED:
			default:
				{
					throw new ArgumentException($"Signature packaging `{parameters.SignaturePackaging}` is not supported in this context.", nameof(parameters));
				}
		}

		if (parameters.DataFormat != null)
		{
			if (!string.IsNullOrEmpty(parameters.DataFormat.TypeIdentifier))
			{
				_dataFormat.ObjectIdentifier = new ObjectIdentifier();
				_dataFormat.ObjectIdentifier.Identifier.IdentifierUri = parameters.DataFormat.TypeIdentifier;
			}

			_dataFormat.Description = parameters.DataFormat.Description;
		}

		SetSignatureId(signatureDocument.XadesSignature);

		PrepareSignatureForRemoteSigning(signatureDocument, parameters);

		digest = signatureDocument.XadesSignature.ComputeSignature();

		return signatureDocument;
	}

	/// <inheritdoc/>
	public SignatureDocument AttachSignature(SignatureDocument document, byte[] signatureValue)
	{
		if (document is null)
		{
			throw new ArgumentNullException(nameof(document));
		}

		if (signatureValue is null)
		{
			throw new ArgumentNullException(nameof(signatureValue));
		}

		// Updated signature value
		document.XadesSignature.Signature.SignatureValue = signatureValue;

		// Update XML
		UpdateXadesSignature(document);

		return document;
	}

	/// <inheritdoc/>
	public SignatureDocument[] Load(Stream stream)
	{
		if (stream is null)
		{
			throw new ArgumentNullException(nameof(stream));
		}

		return Load(XmlUtils.LoadDocument(stream));
	}

	/// <inheritdoc/>
	public SignatureDocument[] Load(string fileName)
	{
		if (fileName is null)
		{
			throw new ArgumentNullException(nameof(fileName));
		}

		using FileStream fileStream = File.OpenRead(fileName);

		return Load(fileStream);
	}

	/// <inheritdoc/>
	public SignatureDocument[] Load(XmlDocument xmlDocument)
	{
		if (xmlDocument is null)
		{
			throw new ArgumentNullException(nameof(xmlDocument));
		}

		XmlNodeList signatureNodeList = xmlDocument.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);
		if (signatureNodeList.Count <= 0)
		{
			return Array.Empty<SignatureDocument>();
		}

		var signatureDocuments = new List<SignatureDocument>();

		foreach (XmlElement signatureNode in signatureNodeList)
		{
			var signatureDocument = new SignatureDocument
			{
				Document = (XmlDocument)xmlDocument.Clone(),
			};
			signatureDocument.Document.PreserveWhitespace = true;
			signatureDocument.XadesSignature = new XadesSignedXml(signatureDocument.Document);
			signatureDocument.XadesSignature.LoadXml(signatureNode);

			signatureDocuments.Add(signatureDocument);
		}

		return signatureDocuments.ToArray();
	}

	/// <inheritdoc/>
	public ValidationResult Validate(SignatureDocument signatureDocument)
	{
		if (signatureDocument is null)
		{
			throw new ArgumentNullException(nameof(signatureDocument));
		}

		SignatureDocument.CheckSignatureDocument(signatureDocument);

		return XadesValidator.Validate(signatureDocument);
	}

	/// <inheritdoc/>
	public ValidationResult Validate(SignatureDocument signatureDocument, XadesValidationFlags validationFlags, bool validateTimestamps)
	{
		if (signatureDocument is null)
		{
			throw new ArgumentNullException(nameof(signatureDocument));
		}

		SignatureDocument.CheckSignatureDocument(signatureDocument);

		return XadesValidator.Validate(signatureDocument, validationFlags, validateTimestamps);
	}

	#endregion

	private void SetSignatureId(XadesSignedXml xadesSignedXml)
	{
		string id = Guid.NewGuid().ToString();

		xadesSignedXml.Signature.Id = "Signature-" + id;
		xadesSignedXml.SignatureValueId = "SignatureValue-" + id;
	}

	private void SetContentInternallyDetached(SignatureDocument sigDocument, XmlDocument xmlDocument, string elementId)
	{
		sigDocument.Document = xmlDocument;

		_refContent = new Reference
		{
			Uri = "#" + elementId,
			Id = "Reference-" + Guid.NewGuid().ToString()
		};

		if (_dataFormat.MimeType == "text/xml")
		{
			var transform = new XmlDsigC14NTransform();
			_refContent.AddTransform(transform);
		}
		else
		{
			var transform = new XmlDsigBase64Transform();
			_refContent.AddTransform(transform);
		}

		sigDocument.XadesSignature = new XadesSignedXml(sigDocument.Document);

		sigDocument.XadesSignature.AddReference(_refContent);
	}

	private void SetContentInternallyDetached(SignatureDocument sigDocument, Stream input)
	{
		sigDocument.Document = new XmlDocument();

		XmlElement rootElement = sigDocument.Document.CreateElement("DOCFIRMA");
		sigDocument.Document.AppendChild(rootElement);

		string id = "CONTENT-" + Guid.NewGuid().ToString();

		_refContent = new Reference
		{
			Uri = "#" + id,
			Id = "Reference-" + Guid.NewGuid().ToString(),
			Type = XadesSignedXml.XmlDsigObjectType
		};

		XmlElement contentElement = sigDocument.Document.CreateElement("CONTENT");

		if (_dataFormat.MimeType == "text/xml")
		{
			var doc = new XmlDocument
			{
				PreserveWhitespace = true
			};
			doc.Load(input);

			contentElement.InnerXml = doc.DocumentElement.OuterXml;

			var transform = new XmlDsigC14NTransform();
			_refContent.AddTransform(transform);
		}
		else
		{
			var transform = new XmlDsigBase64Transform();
			_refContent.AddTransform(transform);

			using var ms = new MemoryStream();
			input.CopyTo(ms);
			contentElement.InnerText = Convert.ToBase64String(ms.ToArray(), Base64FormattingOptions.InsertLineBreaks);
		}

		contentElement.SetAttribute("Id", id);
		contentElement.SetAttribute("MimeType", _dataFormat.MimeType);
		contentElement.SetAttribute("Encoding", _dataFormat.Encoding);


		rootElement.AppendChild(contentElement);

		sigDocument.XadesSignature = new XadesSignedXml(sigDocument.Document);

		sigDocument.XadesSignature.AddReference(_refContent);
	}

	private void SetContentInternallyDetachedHashed(SignatureDocument sigDocument, Stream input)
	{
		sigDocument.Document = new XmlDocument();

		XmlElement rootElement = sigDocument.Document.CreateElement("DOCFIRMA");
		sigDocument.Document.AppendChild(rootElement);

		string id = "CONTENT-" + Guid.NewGuid().ToString();

		_refContent = new Reference
		{
			Uri = "#" + id,
			Id = "Reference-" + Guid.NewGuid().ToString(),
			Type = XadesSignedXml.XmlDsigObjectType
		};

		XmlElement contentElement = sigDocument.Document.CreateElement("CONTENT");

		var transform = new XmlDsigBase64Transform();
		_refContent.AddTransform(transform);

		using (var sha2 = SHA256.Create())
		{
			contentElement.InnerText = Convert.ToBase64String(sha2.ComputeHash(input));
		}

		contentElement.SetAttribute("Id", id);
		contentElement.SetAttribute("MimeType", _dataFormat.MimeType);
		contentElement.SetAttribute("Encoding", _dataFormat.Encoding);

		rootElement.AppendChild(contentElement);

		sigDocument.XadesSignature = new XadesSignedXml(sigDocument.Document);

		sigDocument.XadesSignature.AddReference(_refContent);
	}

	private void SetContentEveloping(SignatureDocument sigDocument, XmlDocument xmlDocument)
	{
		_refContent = new Reference();

		sigDocument.XadesSignature = new XadesSignedXml();

		var doc = (XmlDocument)xmlDocument.Clone();
		doc.PreserveWhitespace = true;

		if (doc.ChildNodes[0].NodeType == XmlNodeType.XmlDeclaration)
		{
			doc.RemoveChild(doc.ChildNodes[0]);
		}

		//Add an object
		string dataObjectId = "DataObject-" + Guid.NewGuid().ToString();
		var dataObject = new DataObject
		{
			Data = doc.ChildNodes,
			Id = dataObjectId
		};
		sigDocument.XadesSignature.AddObject(dataObject);

		_refContent.Id = "Reference-" + Guid.NewGuid().ToString();
		_refContent.Uri = "#" + dataObjectId;
		_refContent.Type = XadesSignedXml.XmlDsigObjectType;

		var transform = new XmlDsigC14NTransform();
		_refContent.AddTransform(transform);

		sigDocument.XadesSignature.AddReference(_refContent);
	}

	private void SetSignatureDestination(SignatureDocument signatureDocument, SignatureXPathExpression destination)
	{
		XmlNode node;

		if (destination.Namespaces.Count > 0)
		{
			var xmlnsMgr = new XmlNamespaceManager(signatureDocument.Document.NameTable);
			foreach (KeyValuePair<string, string> item in destination.Namespaces)
			{
				xmlnsMgr.AddNamespace(item.Key, item.Value);
			}

			node = signatureDocument.Document.SelectSingleNode(destination.XPathExpression, xmlnsMgr);
		}
		else
		{
			node = signatureDocument.Document.SelectSingleNode(destination.XPathExpression);
		}

		if (node == null)
		{
			throw new Exception($"Element `{destination.XPathExpression}` was not found.");
		}

		signatureDocument.XadesSignature.SignatureNodeDestination = (XmlElement)node;
	}

	private void SetContentExternallyDetached(SignatureDocument sigDocument, string fileName)
	{
		_refContent = new Reference();

		sigDocument.Document = new XmlDocument();
		sigDocument.XadesSignature = new XadesSignedXml(sigDocument.Document);

		_refContent.Uri = new Uri(fileName).AbsoluteUri;
		_refContent.Id = "Reference-" + Guid.NewGuid().ToString();

		if (_refContent.Uri.EndsWith(".xml") || _refContent.Uri.EndsWith(".XML"))
		{
			_dataFormat.MimeType = "text/xml";

			_refContent.AddTransform(new XmlDsigC14NTransform());
		}


		sigDocument.XadesSignature.AddReference(_refContent);
	}

	private void AddXPathTransform(SignatureDocument sigDocument, Dictionary<string, string> namespaces, string XPathString)
	{
		XmlDocument document;

		if (sigDocument.Document != null)
		{
			document = sigDocument.Document;
		}
		else
		{
			document = new XmlDocument();
		}

		XmlElement xPathElem = document.CreateElement("XPath");

		foreach (KeyValuePair<string, string> ns in namespaces)
		{
			XmlAttribute attr = document.CreateAttribute("xmlns:" + ns.Key);
			attr.Value = ns.Value;

			xPathElem.Attributes.Append(attr);
		}

		xPathElem.InnerText = XPathString;

		var transform = new XmlDsigXPathTransform();

		transform.LoadInnerXml(xPathElem.SelectNodes("."));

		var reference = sigDocument.XadesSignature.SignedInfo.References[0] as Reference;

		reference.AddTransform(transform);
	}

	private void SetContentEnveloped(SignatureDocument sigDocument, XmlDocument xmlDocument)
	{
		sigDocument.Document = xmlDocument;

		_refContent = new Reference();

		sigDocument.XadesSignature = new XadesSignedXml(sigDocument.Document);

		_refContent.Id = "Reference-" + Guid.NewGuid().ToString();
		_refContent.Uri = "";

		_dataFormat = new DataObjectFormat
		{
			MimeType = "text/xml",
			Encoding = "UTF-8"
		};

		for (int i = 0; i < sigDocument.Document.DocumentElement.Attributes.Count; i++)
		{
			if (sigDocument.Document.DocumentElement.Attributes[i].Name.Equals("id", StringComparison.InvariantCultureIgnoreCase))
			{
				_refContent.Uri = "#" + sigDocument.Document.DocumentElement.Attributes[i].Value;
				break;
			}
		}

		var xmlDsigEnvelopedSignatureTransform = new XmlDsigEnvelopedSignatureTransform();
		_refContent.AddTransform(xmlDsigEnvelopedSignatureTransform);


		sigDocument.XadesSignature.AddReference(_refContent);
	}

	private void PrepareSignature(SignatureDocument sigDocument, LocalSignatureParameters parameters)
	{
		sigDocument.XadesSignature.SignedInfo.SignatureMethod = parameters.SignatureMethod.URI;

		AddCertificateInfo(sigDocument, parameters.Signer.Certificate);
		AddXadesInfo(sigDocument, parameters, parameters.Signer.Certificate);

		foreach (Reference reference in sigDocument.XadesSignature.SignedInfo.References)
		{
			reference.DigestMethod = parameters.DigestMethod.Uri;
		}

		if (parameters.SignatureDestination != null)
		{
			SetSignatureDestination(sigDocument, parameters.SignatureDestination);
		}

		if (parameters.XPathTransformations.Count > 0)
		{
			foreach (SignatureXPathExpression xPathTrans in parameters.XPathTransformations)
			{
				AddXPathTransform(sigDocument, xPathTrans.Namespaces, xPathTrans.XPathExpression);
			}
		}
	}

	private void PrepareSignatureForRemoteSigning(SignatureDocument sigDocument, RemoteSignatureParameters parameters)
	{
		sigDocument.XadesSignature.SignedInfo.SignatureMethod = parameters.SignatureMethod.URI;

		AddCertificateInfo(sigDocument, parameters.PublicCertificate);
		AddXadesInfo(sigDocument, parameters, parameters.PublicCertificate);

		foreach (Reference reference in sigDocument.XadesSignature.SignedInfo.References)
		{
			reference.DigestMethod = parameters.DigestMethod.Uri;
		}

		if (parameters.SignatureDestination != null)
		{
			SetSignatureDestination(sigDocument, parameters.SignatureDestination);
		}

		if (parameters.XPathTransformations.Count > 0)
		{
			foreach (SignatureXPathExpression xPathTrans in parameters.XPathTransformations)
			{
				AddXPathTransform(sigDocument, xPathTrans.Namespaces, xPathTrans.XPathExpression);
			}
		}
	}

	private void UpdateXadesSignature(SignatureDocument sigDocument)
	{
		sigDocument.UpdateDocument();

		var signatureElement = (XmlElement)sigDocument.Document.SelectSingleNode("//*[@Id='" + sigDocument.XadesSignature.Signature.Id + "']");

		// Hay que recargar la firma para que la validación sea correcta ¿¿??
		sigDocument.XadesSignature = new XadesSignedXml(sigDocument.Document);
		sigDocument.XadesSignature.LoadXml(signatureElement);
	}

	private void AddXadesInfo(SignatureDocument sigDocument,
		SignatureParametersBase parameters,
		X509Certificate2 certificate)
	{
		var xadesObject = new XadesObject
		{
			Id = $"XadesObjectId-{Guid.NewGuid()}",
		};
		xadesObject.QualifyingProperties.Id = $"QualifyingProperties-{Guid.NewGuid()}";
		xadesObject.QualifyingProperties.Target = $"#{sigDocument.XadesSignature.Signature.Id}";
		xadesObject.QualifyingProperties.SignedProperties.Id = $"SignedProperties-{sigDocument.XadesSignature.Signature.Id}";

		AddSignatureProperties(sigDocument,
			xadesObject.QualifyingProperties.SignedProperties.SignedSignatureProperties,
			xadesObject.QualifyingProperties.SignedProperties.SignedDataObjectProperties,
			parameters,
			certificate);

		sigDocument.XadesSignature.AddXadesObject(xadesObject);
	}

	private void AddCertificateInfo(SignatureDocument sigDocument, X509Certificate2 certificate)
	{
		// Compute temporary signature via RSA signing key
		sigDocument.XadesSignature.SigningKey = certificate.HasPrivateKey
			? certificate.GetRSAPrivateKey()
			: RSA.Create();

		var keyInfo = new KeyInfo
		{
			Id = $"KeyInfoId-{sigDocument.XadesSignature.Signature.Id}",
		};

		// Add key information
		keyInfo.AddClause(new KeyInfoX509Data(certificate));
		keyInfo.AddClause(new RSAKeyValue(certificate.GetRSAPublicKey()));

		sigDocument.XadesSignature.KeyInfo = keyInfo;

		var reference = new Reference
		{
			Id = "ReferenceKeyInfo",
			Uri = $"#KeyInfoId-{sigDocument.XadesSignature.Signature.Id}",
		};

		sigDocument.XadesSignature.AddReference(reference);
	}

	private void AddSignatureProperties(SignatureDocument sigDocument,
		SignedSignatureProperties signedSignatureProperties,
		SignedDataObjectProperties signedDataObjectProperties,
		SignatureParametersBase parameters,
		X509Certificate2 certificate)
	{
		var xadesCertificate = new Cert();
		xadesCertificate.IssuerSerial.X509IssuerName = certificate.IssuerName.Name;
		xadesCertificate.IssuerSerial.X509SerialNumber = certificate.GetSerialNumberAsDecimalString();
		xadesCertificate.CertDigest.DigestMethod.Algorithm = parameters.DigestMethod.Uri;
		xadesCertificate.CertDigest.DigestValue = parameters.DigestMethod.ComputeHash(certificate.GetRawCertData());

		signedSignatureProperties.SigningCertificate.CertCollection.Add(xadesCertificate);

		if (parameters.SignaturePolicyInfo != null)
		{
			if (!string.IsNullOrEmpty(parameters.SignaturePolicyInfo.PolicyIdentifier))
			{
				signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyImplied = false;
				signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyId.Identifier.IdentifierUri = parameters.SignaturePolicyInfo.PolicyIdentifier;
			}

			if (!string.IsNullOrEmpty(parameters.SignaturePolicyInfo.PolicyUri))
			{
				var spq = new SigPolicyQualifier
				{
					AnyXmlElement = sigDocument.Document.CreateElement(XadesSignedXml.XmlXadesPrefix, "SPURI", XadesSignedXml.XadesNamespaceUri),
				};
				spq.AnyXmlElement.InnerText = parameters.SignaturePolicyInfo.PolicyUri;

				signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyQualifiers.SigPolicyQualifierCollection.Add(spq);
			}

			if (!string.IsNullOrEmpty(parameters.SignaturePolicyInfo.PolicyHash))
			{
				signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyHash.DigestMethod.Algorithm = parameters.SignaturePolicyInfo.PolicyDigestAlgorithm.Uri;
				signedSignatureProperties.SignaturePolicyIdentifier.SignaturePolicyId.SigPolicyHash.DigestValue = Convert.FromBase64String(parameters.SignaturePolicyInfo.PolicyHash);
			}
		}

		signedSignatureProperties.SigningTime = parameters.SigningDate ?? DateTime.Now;

		if (_dataFormat != null)
		{
			var newDataObjectFormat = new DataObjectFormat
			{
				MimeType = _dataFormat.MimeType,
				Encoding = _dataFormat.Encoding,
				Description = _dataFormat.Description,
				ObjectReferenceAttribute = $"#{_refContent.Id}",
			};

			if (_dataFormat.ObjectIdentifier != null)
			{
				newDataObjectFormat.ObjectIdentifier.Identifier.IdentifierUri = _dataFormat.ObjectIdentifier.Identifier.IdentifierUri;
			}

			signedDataObjectProperties.DataObjectFormatCollection.Add(newDataObjectFormat);
		}

		if (parameters.SignerRole != null &&
			(parameters.SignerRole.CertifiedRoles.Count > 0 || parameters.SignerRole.ClaimedRoles.Count > 0))
		{
			signedSignatureProperties.SignerRole = new Microsoft.Xades.SignerRole();

			foreach (X509Certificate certifiedRole in parameters.SignerRole.CertifiedRoles)
			{
				signedSignatureProperties.SignerRole.CertifiedRoles.CertifiedRoleCollection.Add(new CertifiedRole()
				{
					PkiData = certifiedRole.GetRawCertData(),
				});
			}

			foreach (string claimedRole in parameters.SignerRole.ClaimedRoles)
			{
				signedSignatureProperties.SignerRole.ClaimedRoles.ClaimedRoleCollection.Add(new ClaimedRole() { InnerText = claimedRole });
			}
		}

		foreach (SignatureCommitment signatureCommitment in parameters.SignatureCommitments)
		{
			var cti = new CommitmentTypeIndication();
			cti.CommitmentTypeId.Identifier.IdentifierUri = signatureCommitment.CommitmentType.URI;
			cti.AllSignedDataObjects = true;

			foreach (XmlElement signatureCommitmentQualifier in signatureCommitment.CommitmentTypeQualifiers)
			{
				var ctq = new CommitmentTypeQualifier
				{
					AnyXmlElement = signatureCommitmentQualifier
				};

				cti.CommitmentTypeQualifiers.CommitmentTypeQualifierCollection.Add(ctq);
			}

			signedDataObjectProperties.CommitmentTypeIndicationCollection.Add(cti);
		}

		if (parameters.SignatureProductionPlace != null)
		{
			signedSignatureProperties.SignatureProductionPlace.City = parameters.SignatureProductionPlace.City;
			signedSignatureProperties.SignatureProductionPlace.StateOrProvince = parameters.SignatureProductionPlace.StateOrProvince;
			signedSignatureProperties.SignatureProductionPlace.PostalCode = parameters.SignatureProductionPlace.PostalCode;
			signedSignatureProperties.SignatureProductionPlace.CountryName = parameters.SignatureProductionPlace.CountryName;
		}
	}
}
