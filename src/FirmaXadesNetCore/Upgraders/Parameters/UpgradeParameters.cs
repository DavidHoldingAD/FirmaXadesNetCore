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
using FirmaXadesNetCore.Crypto;
using Org.BouncyCastle.X509;

namespace FirmaXadesNetCore.Upgraders.Parameters;

public class UpgradeParameters
{
	private readonly List<X509Crl> _crls = new();
	private readonly X509CrlParser _crlParser = new();

	public List<OcspServer> OCSPServers { get; } = new();

	public IEnumerable<X509Crl> CRL => _crls;

	public DigestMethod DigestMethod { get; set; } = DigestMethod.SHA1;

	public ITimeStampClient TimeStampClient { get; set; }

	public bool GetOcspUrlFromCertificate { get; set; } = true;

	public void AddCRL(Stream stream)
	{
		if (stream is null)
		{
			throw new ArgumentNullException(nameof(stream));
		}

		_crls.Add(_crlParser.ReadCrl(stream));
	}

	public void ClearCRL()
		=> _crls.Clear();
}
