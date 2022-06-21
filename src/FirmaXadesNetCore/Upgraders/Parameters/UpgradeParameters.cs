// --------------------------------------------------------------------------------------------------------------------
// UpgradeParameters.cs
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

using FirmaXadesNetCore.Clients;
using Org.BouncyCastle.X509;

namespace FirmaXadesNetCore.Upgraders.Parameters;

/// <summary>
/// Represents a upgrade parameters.
/// </summary>
public class UpgradeParameters
{
	private readonly List<X509Crl> _crls = new();
	private readonly X509CrlParser _crlParser = new();

	/// <summary>
	/// Gets the OCSP servers.
	/// </summary>
	public List<OcspServer> OcspServers { get; } = new();

	/// <summary>
	/// Gets the CRLS.
	/// </summary>
	public IEnumerable<X509Crl> Crls
		=> _crls;

	/// <summary>
	/// Gets or sets the digest method.
	/// </summary>
	public DigestMethod DigestMethod { get; set; } = DigestMethod.SHA1;

	/// <summary>
	/// Gets or sets the timestamp client.
	/// </summary>
	public ITimestampClient TimestampClient { get; }

	/// <summary>
	/// Gets or sets a flag indicating whether to get the OCSP URL from certificate or not.
	/// </summary>
	public bool GetOcspUrlFromCertificate { get; set; } = true;

	/// <summary>
	/// Initializes a new instance of <see cref="UpgradeParameters"/> class.
	/// </summary>
	/// <param name="timestampClient">the timestamp client</param>
	public UpgradeParameters(ITimestampClient timestampClient)
	{
		TimestampClient = timestampClient ?? throw new ArgumentNullException(nameof(timestampClient));
	}

	/// <summary>
	/// Adds a CRL.
	/// </summary>
	/// <param name="stream">the CRL stream</param>
	public void AddCrl(Stream stream)
	{
		if (stream is null)
		{
			throw new ArgumentNullException(nameof(stream));
		}

		_crls.Add(_crlParser.ReadCrl(stream));
	}

	/// <summary>
	/// Clears the CRLs.
	/// </summary>
	public void ClearCrls()
		=> _crls.Clear();
}
