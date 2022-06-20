// --------------------------------------------------------------------------------------------------------------------
// SignatureCommitmentType.cs
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
// along with this program.  If not, see https://www.gnu.org/licenses/lgpl-3.0.txt. 
//
// E-Mail: informatica@gemuc.es
// 
// --------------------------------------------------------------------------------------------------------------------

namespace FirmaXadesNetCore;

/// <summary>
/// Represents a XAdES signature commitment type.
/// </summary>
public sealed class SignatureCommitmentType
{
	/// <summary>
	/// ProofOfOrigin
	/// </summary>
	public static readonly SignatureCommitmentType ProofOfOrigin = new("http://uri.etsi.org/01903/v1.2.2#ProofOfOrigin");

	/// <summary>
	/// ProofOfReceipt
	/// </summary>
	public static readonly SignatureCommitmentType ProofOfReceipt = new("http://uri.etsi.org/01903/v1.2.2#ProofOfReceipt");

	/// <summary>
	/// ProofOfDelivery
	/// </summary>
	public static readonly SignatureCommitmentType ProofOfDelivery = new("http://uri.etsi.org/01903/v1.2.2#ProofOfDelivery");

	/// <summary>
	/// ProofOfSender
	/// </summary>
	public static readonly SignatureCommitmentType ProofOfSender = new("http://uri.etsi.org/01903/v1.2.2#ProofOfSender");

	/// <summary>
	/// ProofOfApproval
	/// </summary>
	public static readonly SignatureCommitmentType ProofOfApproval = new("http://uri.etsi.org/01903/v1.2.2#ProofOfApproval");

	/// <summary>
	/// ProofOfCreation
	/// </summary>
	public static readonly SignatureCommitmentType ProofOfCreation = new("http://uri.etsi.org/01903/v1.2.2#ProofOfCreation");

	/// <summary>
	/// Gets the URI.
	/// </summary>
	public string Uri { get; }

	/// <summary>
	/// Initializes a new instance of <see cref="SignatureCommitmentType"/> class.
	/// </summary>
	/// <param name="uri">the URI</param>
	public SignatureCommitmentType(string uri)
	{
		Uri = uri ?? throw new ArgumentNullException(nameof(uri));
	}
}
