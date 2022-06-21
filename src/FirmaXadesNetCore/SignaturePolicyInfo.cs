// --------------------------------------------------------------------------------------------------------------------
// SignaturePolicyInfo.cs
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

namespace FirmaXadesNetCore;

/// <summary>
/// Represents a signature policy information.
/// </summary>
public class SignaturePolicyInfo
{
	/// <summary>
	/// Gets or sets the policy identifier.
	/// </summary>
	public string? PolicyIdentifier { get; set; }

	/// <summary>
	/// Gets or sets the policy hash.
	/// </summary>
	public string? PolicyHash { get; set; }

	/// <summary>
	/// Gets or sets the policy digest algorithm.
	/// </summary>
	public DigestMethod PolicyDigestAlgorithm { get; set; } = DigestMethod.SHA1;

	/// <summary>
	/// Gets or sets the policy URI.
	/// </summary>
	public string? PolicyUri { get; set; }
}
