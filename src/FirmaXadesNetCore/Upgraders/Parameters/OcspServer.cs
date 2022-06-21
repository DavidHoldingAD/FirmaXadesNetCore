// --------------------------------------------------------------------------------------------------------------------
// OcspServer.cs
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

using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Asn1.X509;

namespace FirmaXadesNetCore.Upgraders.Parameters;

/// <summary>
/// Represents a OCSP server.
/// </summary>
public class OcspServer
{
	/// <summary>
	/// DirectoryName
	/// </summary>
	public const int DirectoryName = 4;

	/// <summary>
	/// DnsName
	/// </summary>
	public const int DnsName = 2;

	/// <summary>
	/// EdiPartyName
	/// </summary>
	public const int EdiPartyName = 5;

	/// <summary>
	/// IPAddress
	/// </summary>
	public const int IPAddress = 7;

	/// <summary>
	/// OtherName
	/// </summary>
	public const int OtherName = 0;

	/// <summary>
	/// RegisteredID
	/// </summary>
	public const int RegisteredID = 8;

	/// <summary>
	/// Rfc822Name
	/// </summary>
	public const int Rfc822Name = 1;

	/// <summary>
	/// UniformResourceIdentifier
	/// </summary>
	public const int UniformResourceIdentifier = 6;

	/// <summary>
	/// X400Address
	/// </summary>
	public const int X400Address = 3;

	/// <summary>
	/// Gets the URL.
	/// </summary>
	public string Url { get; }

	/// <summary>
	/// Gets the requester name.
	/// </summary>
	public GeneralName? RequestorName { get; private set; }

	/// <summary>
	/// Gets or sets the signing certificate.
	/// </summary>
	public X509Certificate2? SigningCertificate { get; set; }

	/// <summary>
	/// Initializes a new instance of <see cref="OcspServer"/> class.
	/// </summary>
	/// <param name="url">the OSCP server URL</param>
	public OcspServer(string url)
	{
		Url = url ?? throw new ArgumentNullException(nameof(url));
	}

	/// <summary>
	/// Sets the requester tag and name.
	/// </summary>
	/// <param name="tag">the tag</param>
	/// <param name="name">the name</param>
	public void SetRequestorName(int tag, string name)
	{
		if (name is null)
		{
			throw new ArgumentNullException(nameof(name));
		}

		RequestorName = new GeneralName(tag, name);
	}
}
