// --------------------------------------------------------------------------------------------------------------------
// Signer.cs
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

namespace FirmaXadesNetCore.Crypto;

public class Signer : IDisposable
{
	#region Private variables

	private bool _disposeCryptoProvider;

	#endregion

	#region Public properties

	public X509Certificate2 Certificate { get; }

	public AsymmetricAlgorithm SigningKey { get; private set; }

	#endregion

	#region Constructors

	public Signer(X509Certificate2 certificate)
	{
		if (certificate == null)
		{
			throw new ArgumentNullException(nameof(certificate));
		}

		if (!certificate.HasPrivateKey)
		{
			throw new Exception("El certificado no contiene ninguna clave privada");
		}

		Certificate = certificate;

		SetSigningKey(Certificate);
	}

	#endregion

	#region Public methods

	public void Dispose()
	{
		if (_disposeCryptoProvider && SigningKey != null)
		{
			SigningKey.Dispose();
		}
	}

	#endregion

	#region Private methods

	private void SetSigningKey(X509Certificate2 certificate)
	{
		RSA key = certificate.GetRSAPrivateKey();
		SigningKey = key;
		_disposeCryptoProvider = false;
	}

	#endregion
}
