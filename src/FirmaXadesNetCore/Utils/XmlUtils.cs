// --------------------------------------------------------------------------------------------------------------------
// XMLUtil.cs
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

using System.Collections;
using System.Security.Cryptography;
using System.Security.Cryptography.Xml;
using System.Text;
using System.Xml;
using Microsoft.Xades;

namespace FirmaXadesNetCore.Utils;

internal static class XmlUtils
{
	public static byte[] ApplyTransform(XmlElement element, System.Security.Cryptography.Xml.Transform transform)
	{
		if (element is null)
		{
			throw new ArgumentNullException(nameof(element));
		}

		if (transform is null)
		{
			throw new ArgumentNullException(nameof(transform));
		}

		byte[] buffer = Encoding.UTF8.GetBytes(element.OuterXml);

		using var ms = new MemoryStream(buffer);
		transform.LoadInput(ms);
		using var transformedStream = (MemoryStream)transform.GetOutput(typeof(Stream));
		return transformedStream.ToArray();
	}

	public static byte[] ComputeValueOfElementList(XadesSignedXml xadesSignedXml, ArrayList elementXpaths)
	{
		if (xadesSignedXml is null)
		{
			throw new ArgumentNullException(nameof(xadesSignedXml));
		}

		if (elementXpaths is null)
		{
			throw new ArgumentNullException(nameof(elementXpaths));
		}

		return ComputeValueOfElementList(xadesSignedXml, elementXpaths, new XmlDsigC14NTransform());
	}

	public static byte[] ComputeValueOfElementList(XadesSignedXml xadesSignedXml,
		ArrayList elementXpaths,
		System.Security.Cryptography.Xml.Transform transform)
	{
		if (xadesSignedXml is null)
		{
			throw new ArgumentNullException(nameof(xadesSignedXml));
		}

		if (elementXpaths is null)
		{
			throw new ArgumentNullException(nameof(elementXpaths));
		}

		if (transform is null)
		{
			throw new ArgumentNullException(nameof(transform));
		}

		XmlElement signatureXmlElement = xadesSignedXml.GetSignatureElement()!;
		List<XmlAttribute> namespaces = xadesSignedXml.GetAllNamespaces(signatureXmlElement);
		XmlDocument xmlDocument = signatureXmlElement!.OwnerDocument;

		var xmlNamespaceManager = new XmlNamespaceManager(xmlDocument.NameTable);
		xmlNamespaceManager.AddNamespace("ds", SignedXml.XmlDsigNamespaceUrl);
		xmlNamespaceManager.AddNamespace("xades", XadesSignedXml.XadesNamespaceUri);

		using var msResult = new MemoryStream();
		foreach (string elementXpath in elementXpaths)
		{
			XmlNodeList? searchXmlNodeList = signatureXmlElement.SelectNodes(elementXpath, xmlNamespaceManager);
			if (searchXmlNodeList is null
				|| searchXmlNodeList.Count <= 0)
			{
				throw new CryptographicException($"Element `{elementXpath}` not found while calculating hash.");
			}

			foreach (XmlNode xmlNode in searchXmlNodeList)
			{
				var clonedElement = (XmlElement)xmlNode.Clone();

				clonedElement.SetAttribute("xmlns:" + XadesSignedXml.XmlDSigPrefix, SignedXml.XmlDsigNamespaceUrl);

				foreach (XmlAttribute attr in namespaces)
				{
					clonedElement.SetAttribute(attr.Name, attr.Value);
				}

				byte[] canonicalizedElement = ApplyTransform(clonedElement, transform);
				msResult.Write(canonicalizedElement, 0, canonicalizedElement.Length);
			}
		}

		return msResult.ToArray();
	}

	public static XmlDocument LoadDocument(Stream stream)
	{
		if (stream is null)
		{
			throw new ArgumentNullException(nameof(stream));
		}

		var document = new XmlDocument
		{
			PreserveWhitespace = true
		};
		document.Load(stream);

		return document;
	}
}
