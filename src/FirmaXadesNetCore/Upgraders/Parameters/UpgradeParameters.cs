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
	#region Private variables


	private readonly List<X509Crl> _crls;
	private readonly X509CrlParser _crlParser;

	private readonly DigestMethod _defaultDigestMethod = DigestMethod.SHA1;

	#endregion

	#region Public properties

	public List<OcspServer> OCSPServers { get; }

	public IEnumerable<X509Crl> CRL => _crls;

	public DigestMethod DigestMethod { get; set; }

	public ITimeStampClient TimeStampClient { get; set; }

	public bool GetOcspUrlFromCertificate { get; set; }

	#endregion

	#region Constructors

	public UpgradeParameters()
	{
		OCSPServers = new List<OcspServer>();
		_crls = new List<X509Crl>();
		DigestMethod = _defaultDigestMethod;
		_crlParser = new X509CrlParser();
		GetOcspUrlFromCertificate = true;
	}

	#endregion

	#region Public methods

	public void AddCRL(Stream stream)
	{
		X509Crl x509crl = _crlParser.ReadCrl(stream);

		_crls.Add(x509crl);
	}

	public void ClearCRL() => _crls.Clear();

	#endregion
}
