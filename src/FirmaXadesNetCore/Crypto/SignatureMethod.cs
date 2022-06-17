// --------------------------------------------------------------------------------------------------------------------
// SignatureMethod.cs
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
using System.Security.Cryptography.Xml;

namespace FirmaXadesNetCore.Crypto;

public sealed class SignatureMethod
{
	public static readonly SignatureMethod RSAwithSHA1 = new SignatureMethod("RSAwithSHA1", SignedXml.XmlDsigRSASHA1Url);
	public static readonly SignatureMethod RSAwithSHA256 = new SignatureMethod("RSAwithSHA256", SignedXml.XmlDsigRSASHA256Url);
	public static readonly SignatureMethod RSAwithSHA384 = new SignatureMethod("RSAwithSHA384", SignedXml.XmlDsigRSASHA384Url);
	public static readonly SignatureMethod RSAwithSHA512 = new SignatureMethod("RSAwithSHA512", SignedXml.XmlDsigRSASHA512Url);

	public string Name { get; }

	public string URI { get; }

	private SignatureMethod(string name, string uri)
	{
		Name = name;
		URI = uri;
	}

	public SignatureDescription CreateSignatureDescription()
	{
		return URI switch
		{
			SignedXml.XmlDsigRSASHA1Url
				=> new Microsoft.Xades.RSAPKCS1SHA1SignatureDescription(),
			SignedXml.XmlDsigRSASHA256Url
				=> new Microsoft.Xades.RSAPKCS1SHA256SignatureDescription(),
			SignedXml.XmlDsigRSASHA384Url
				=> new Microsoft.Xades.RSAPKCS1SHA384SignatureDescription(),
			SignedXml.XmlDsigRSASHA512Url
				=> new Microsoft.Xades.RSAPKCS1SHA512SignatureDescription(),
			_
				=> throw new Exception($"Signature method URI `{URI}` is not supported in this context.")
		};
	}

	public static SignatureMethod GetByUri(string uri)
	{
		if (uri is null)
		{
			throw new ArgumentNullException(nameof(uri));
		}

		return uri switch
		{
			SignedXml.XmlDsigRSASHA1Url
				=> RSAwithSHA1,
			SignedXml.XmlDsigRSASHA256Url
				=> RSAwithSHA256,
			SignedXml.XmlDsigRSASHA384Url
				=> RSAwithSHA384,
			SignedXml.XmlDsigRSASHA512Url
				=> RSAwithSHA512,
			_
				=> throw new Exception($"Signature method URI `{uri}` is not supported in this context.")
		};
	}
}

