// --------------------------------------------------------------------------------------------------------------------
// SignatureDocument.cs
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

using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using FirmaXadesNetCore.Utils;
using Microsoft.Xades;

namespace FirmaXadesNetCore;

/// <summary>
/// Represents a signature document.
/// </summary>
public class SignatureDocument
{
	/// <summary>
	/// Gets or sets the XML document.
	/// </summary>
	public XmlDocument? Document { get; set; }

	/// <summary>
	/// Gets or sets the XAdES signature.
	/// </summary>
	public XadesSignedXml? XadesSignature { get; set; }

	/// <summary>
	/// Gets the serializes XML document bytes.
	/// </summary>
	/// <returns>the bytes</returns>
	public byte[] GetDocumentBytes()
	{
		using var stream = new MemoryStream();

		Save(stream);

		return stream.ToArray();
	}

	/// <summary>
	/// Save the signature in the specified file.
	/// </summary>
	/// <param name="fileName"></param>
	public void Save(string fileName)
	{
		if (fileName is null)
		{
			throw new ArgumentNullException(nameof(fileName));
		}

		CheckSignatureDocument(this);

		var settings = new XmlWriterSettings
		{
			Encoding = new UTF8Encoding()
		};

		using var writer = XmlWriter.Create(fileName, settings);

		Document!.Save(writer);
	}

	/// <summary>
	/// Save the signature to the specified destination.
	/// </summary>
	/// <param name="stream"></param>
	public void Save(Stream stream)
	{
		if (stream is null)
		{
			throw new ArgumentNullException(nameof(stream));
		}

		CheckSignatureDocument(this);

		var settings = new XmlWriterSettings
		{
			Encoding = new UTF8Encoding(),
		};

		using var writer = XmlWriter.Create(stream, settings);

		Document!.Save(writer);
	}

	/// <summary>
	/// Validates the signature document with the specified options.
	/// </summary>
	/// <param name="validationFlags">the validation flags</param>
	/// <param name="validateTimestamps">a flag indicating whether to validate timestamps or not</param>
	/// <returns>the validation result</returns>
	public ValidationResult Validate(XadesValidationFlags validationFlags = XadesValidationFlags.AllChecks,
		bool validateTimestamps = true)
	{
		ValidationResult validationResult = new XadesService()
			.Validate(this, validationFlags, validateTimestamps);

		return validationResult;
	}

	internal void UpdateDocument()
	{
		Document ??= new XmlDocument();

		if (Document.DocumentElement != null)
		{
			XmlNode? xmlNode = Document.SelectSingleNode($"//*[@Id='{XadesSignature!.Signature.Id}']");
			if (xmlNode != null)
			{
				var nm = new XmlNamespaceManager(Document.NameTable);
				nm.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);
				nm.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);

				XmlNode? xmlQPNode = xmlNode.SelectSingleNode("ds:Object/xades:QualifyingProperties", nm);
				XmlNode? xmlUnsingedPropertiesNode = xmlNode.SelectSingleNode("ds:Object/xades:QualifyingProperties/xades:UnsignedProperties", nm);

				if (xmlUnsingedPropertiesNode != null)
				{
					XmlNode? xmlUnsingedSignaturePropertiesNode = xmlNode
						.SelectSingleNode("ds:Object/xades:QualifyingProperties/xades:UnsignedProperties/xades:UnsignedSignatureProperties", nm);
					XmlElement xmlUnsignedPropertiesNew = XadesSignature.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.GetXml();
					foreach (XmlNode childNode in xmlUnsignedPropertiesNew.ChildNodes)
					{
						if (childNode.Attributes!["Id"] != null &&
							xmlUnsingedSignaturePropertiesNode!.SelectSingleNode($"//*[@Id='{childNode.Attributes!["Id"]!.Value}']") == null)
						{
							XmlNode newNode = Document.ImportNode(childNode, true);
							xmlUnsingedSignaturePropertiesNode.AppendChild(newNode);
						}
					}

					// Se comprueban las ContraFirmas
					if (XadesSignature.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.CounterSignatureCollection.Count > 0)
					{
						foreach (XadesSignedXml counterSign in XadesSignature.XadesObject.QualifyingProperties.UnsignedProperties.UnsignedSignatureProperties.CounterSignatureCollection)
						{
							if (xmlNode.SelectSingleNode("//*[@Id='" + counterSign.Signature.Id + "']") == null)
							{
								XmlNode xmlCounterSignatureNode = Document.CreateElement(XadesSignedXml.XmlXadesPrefix, "CounterSignature", XadesSignedXml.XadesNamespaceUri);
								xmlUnsingedSignaturePropertiesNode!.AppendChild(xmlCounterSignatureNode);
								xmlCounterSignatureNode.AppendChild(Document.ImportNode(counterSign.GetXml(), true));
							}
						}
					}
				}
				else
				{
					xmlUnsingedPropertiesNode = Document.ImportNode(XadesSignature.XadesObject.QualifyingProperties.UnsignedProperties.GetXml(), true);
					xmlQPNode!.AppendChild(xmlUnsingedPropertiesNode);
				}
			}
			else
			{
				XmlElement xmlSigned = XadesSignature.GetXml();

				byte[] canonicalizedElement = XmlUtils.ApplyTransform(xmlSigned, new XmlDsigC14NTransform());

				var doc = new XmlDocument
				{
					PreserveWhitespace = true
				};
				doc.LoadXml(Encoding.UTF8.GetString(canonicalizedElement));

				XmlNode canonSignature = Document.ImportNode(doc.DocumentElement!, true);

				XadesSignature.GetSignatureElement()?.AppendChild(canonSignature);
			}
		}
		else
		{
			Document.LoadXml(XadesSignature!.GetXml().OuterXml);
		}
	}

	internal static void CheckSignatureDocument(SignatureDocument sigDocument)
	{
		if (sigDocument is null)
		{
			throw new ArgumentNullException(nameof(sigDocument));
		}

		if (sigDocument.Document is null || sigDocument.XadesSignature is null)
		{
			throw new Exception("There is no information about the firm.");
		}
	}
}
