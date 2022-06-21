// --------------------------------------------------------------------------------------------------------------------
// ITimeStampClient.cs
//
// FirmaXadesNet - Librería para la generación de firmas XADES
// Copyright (C) 2017 Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
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

namespace FirmaXadesNetCore.Clients;

/// <summary>
/// Provides a mechanism for remotely time-stamping hashes.
/// </summary>
public interface ITimeStampClient
{
	/// <summary>
	/// Makes the sealing request of the hash that is passed as a parameter and returns the response from the server.
	/// </summary>
	/// <param name="hashValue"></param>
	/// <param name="digestMethod"></param>
	/// <param name="cerrequestSignerCertificatesReq"></param>
	/// <param name="cancellationToken"></param>
	/// <returns></returns>
	Task<byte[]> GetTimeStampAsync(byte[] hashValue,
		DigestMethod digestMethod,
		bool cerrequestSignerCertificatesReq,
		CancellationToken cancellationToken);
}
