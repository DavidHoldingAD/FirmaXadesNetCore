// --------------------------------------------------------------------------------------------------------------------
// SignatureParameters.cs
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
/// Represents a remote signature parameters.
/// </summary>
public sealed class RemoteSignatureParameters : SignatureParametersBase
{
	/// <summary>
	/// Gets or sets the public certificate.
	/// </summary>
	public X509Certificate2 PublicCertificate { get; }

	/// <summary>
	/// Initializes a new instance of <see cref="RemoteSignatureParameters"/> class.
	/// </summary>
	/// <param name="certificate">the public certificate</param>
	public RemoteSignatureParameters(X509Certificate2 certificate)
	{
		PublicCertificate = certificate ?? throw new ArgumentNullException(nameof(certificate));
	}
}
