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

using System.Security.Cryptography.X509Certificates;

namespace FirmaXadesNetCore;

/// <summary>
/// Represents a signer.
/// </summary>
public class Signer
{
	/// <summary>
	/// Gets the certificate.
	/// </summary>
	public X509Certificate2 Certificate { get; }

	/// <summary>
	/// Initializes a new instance of <see cref="Signer"/> class.
	/// </summary>
	/// <param name="certificate">the certificate</param>
	public Signer(X509Certificate2 certificate)
	{
		if (certificate is null)
		{
			throw new ArgumentNullException(nameof(certificate));
		}

		if (!certificate.HasPrivateKey)
		{
			throw new Exception("The certificate does not contain any private key.");
		}

		Certificate = certificate;
	}
}
