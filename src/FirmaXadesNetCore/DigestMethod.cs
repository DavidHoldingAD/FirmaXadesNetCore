﻿// --------------------------------------------------------------------------------------------------------------------
// DigestMethod.cs
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

namespace FirmaXadesNetCore;

/// <summary>
/// Represents a digest method.
/// </summary>
public sealed class DigestMethod
{
	private const string Sha1OID = "1.3.14.3.2.26";
	private const string Sha256OID = "2.16.840.1.101.3.4.2.1";
	private const string Sha384OID = "2.16.840.1.101.3.4.2.2";
	private const string Sha512OID = "2.16.840.1.101.3.4.2.3";

	/// <summary>
	/// SHA-1
	/// </summary>
	public static readonly DigestMethod SHA1 = new("SHA1", SignedXml.XmlDsigSHA1Url, Sha1OID);

	/// <summary>
	/// SHA-256
	/// </summary>
	public static readonly DigestMethod SHA256 = new("SHA256", SignedXml.XmlDsigSHA256Url, Sha256OID);

	/// <summary>
	/// SHA-384
	/// </summary>
	public static readonly DigestMethod SHA384 = new("SHA384", SignedXml.XmlDsigSHA384Url, Sha384OID);

	/// <summary>
	/// SHA-512
	/// </summary>
	public static readonly DigestMethod SHA512 = new("SHA512", SignedXml.XmlDsigSHA512Url, Sha512OID);

	/// <summary>
	/// Gets the name.
	/// </summary>
	public string Name { get; }

	/// <summary>
	/// Gets the URI.
	/// </summary>
	public string Uri { get; }

	/// <summary>
	/// Gets the OID.
	/// </summary>
	public string Oid { get; }

	private DigestMethod(string name, string uri, string oid)
	{
		Name = name;
		Uri = uri;
		Oid = oid;
	}

	/// <summary>
	/// Gets the hash algorithm name.
	/// </summary>
	/// <returns>the name</returns>
	public HashAlgorithmName GetHashAlgorithmName()
	{
		return Uri switch
		{
			SignedXml.XmlDsigSHA1Url
				=> HashAlgorithmName.SHA1,
			SignedXml.XmlDsigSHA256Url
				=> HashAlgorithmName.SHA256,
			SignedXml.XmlDsigSHA384Url
				=> HashAlgorithmName.SHA384,
			SignedXml.XmlDsigSHA512Url
				=> HashAlgorithmName.SHA512,
			_
				=> throw new Exception($"Hash algorithm URI `{Uri}` is not supported in this context.")
		};
	}

	/// <summary>
	/// Creates the hash algorithm.
	/// </summary>
	/// <returns>the algorithm</returns>
	public HashAlgorithm Create()
	{
		return Name switch
		{
			"SHA1"
				=> System.Security.Cryptography.SHA1.Create(),
			"SHA256"
				=> System.Security.Cryptography.SHA256.Create(),
			"SHA384"
				=> System.Security.Cryptography.SHA384.Create(),
			"SHA512"
				=> System.Security.Cryptography.SHA512.Create(),
			_
				=> throw new Exception($"Hash algorithm name `{Name}` is not supported in this context.")
		};
	}

	/// <summary>
	/// Computes the hash for the specified value.
	/// </summary>
	/// <param name="value">the value</param>
	/// <returns>the hash</returns>
	public byte[] ComputeHash(byte[] value)
	{
		if (value is null)
		{
			throw new ArgumentNullException(nameof(value));
		}

#if NET6_0_OR_GREATER
		return Uri switch
		{
			SignedXml.XmlDsigSHA1Url
				=> System.Security.Cryptography.SHA1.HashData(value),
			SignedXml.XmlDsigSHA256Url
				=> System.Security.Cryptography.SHA256.HashData(value),
			SignedXml.XmlDsigSHA384Url
				=> System.Security.Cryptography.SHA384.HashData(value),
			SignedXml.XmlDsigSHA512Url
				=> System.Security.Cryptography.SHA512.HashData(value),
			_
				=> throw new Exception($"Hash algorithm URI `{Uri}` is not supported in this context.")
		};
#else
		using HashAlgorithm hashAlgorithm = Uri switch
		{
			SignedXml.XmlDsigSHA1Url
				=> HashAlgorithm.Create(HashAlgorithmName.SHA1.Name),
			SignedXml.XmlDsigSHA256Url
				=> HashAlgorithm.Create(HashAlgorithmName.SHA256.Name),
			SignedXml.XmlDsigSHA384Url
				=> HashAlgorithm.Create(HashAlgorithmName.SHA384.Name),
			SignedXml.XmlDsigSHA512Url
				=> HashAlgorithm.Create(HashAlgorithmName.SHA512.Name),
			_
				=> throw new Exception($"Hash algorithm URI `{Uri}` is not supported in this context.")
		};

		return hashAlgorithm.ComputeHash(value);
#endif
	}

	/// <summary>
	/// Gets the digest method by OID.
	/// </summary>
	/// <param name="oid">the OID</param>
	/// <returns>the method</returns>
	public static DigestMethod GetByOid(string oid)
	{
		if (oid is null)
		{
			throw new ArgumentNullException(nameof(oid));
		}

		return oid switch
		{
			Sha1OID
				=> SHA1,
			Sha256OID
				=> SHA256,
			Sha384OID
				=> SHA384,
			Sha512OID
				=> SHA512,
			_
				=> throw new Exception($"Hash algorithm OID `{oid}` is not supported in this context.")
		};
	}

	/// <summary>
	/// Gets the digest method by URI.
	/// </summary>
	/// <param name="uri">the URI</param>
	/// <returns>the method</returns>
	public static DigestMethod GetByUri(string uri)
	{
		if (uri is null)
		{
			throw new ArgumentNullException(nameof(uri));
		}

		return uri switch
		{
			SignedXml.XmlDsigSHA1Url
				=> SHA1,
			SignedXml.XmlDsigSHA256Url
				=> SHA256,
			SignedXml.XmlDsigSHA384Url
				=> SHA384,
			SignedXml.XmlDsigSHA512Url
				=> SHA512,
			_
				=> throw new Exception($"Hash algorithm URI `{uri}` is not supported in this context.")
		};
	}
}
