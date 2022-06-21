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

namespace FirmaXadesNetCore;

/// <summary>
/// Represents a base signature parameters.
/// </summary>
public abstract class SignatureParametersBase
{
	/// <summary>
	/// Gets or sets the signature method.
	/// </summary>
	public SignatureMethod SignatureMethod { get; set; } = SignatureMethod.RSAwithSHA256;

	/// <summary>
	/// Gets or sets the digest method.
	/// </summary>
	public DigestMethod DigestMethod { get; set; } = DigestMethod.SHA256;

	/// <summary>
	/// Gets or sets the signing date.
	/// </summary>
	public DateTime? SigningDate { get; set; }

	/// <summary>
	/// Gets or sets the signer role.
	/// </summary>
	public SignerRole? SignerRole { get; set; }

	/// <summary>
	/// Gets or sets the signature commitments.
	/// </summary>
	public List<SignatureCommitment> SignatureCommitments { get; } = new();

	/// <summary>
	/// Gets or sets the signature production place.
	/// </summary>
	public SignatureProductionPlace? SignatureProductionPlace { get; set; }

	/// <summary>
	/// Gets or sets the XPath transformations.
	/// </summary>
	public List<SignatureXPathExpression> XPathTransformations { get; } = new();

	/// <summary>
	/// Gets or sets the signature policy information.
	/// </summary>
	public SignaturePolicyInfo? SignaturePolicyInfo { get; set; }

	/// <summary>
	/// Gets or sets the signature destination.
	/// </summary>
	public SignatureXPathExpression? SignatureDestination { get; set; }

	/// <summary>
	/// Gets or sets the signature packaging.
	/// </summary>
	public SignaturePackaging SignaturePackaging { get; set; }

	/// <summary>
	/// Gets or sets the data format.
	/// </summary>
	public DataFormat? DataFormat { get; set; }

	/// <summary>
	/// Gets or sets the element ID to sign.
	/// </summary>
	public string? ElementIdToSign { get; set; }

	/// <summary>
	/// Gets or sets the external content URI.
	/// </summary>
	public string? ExternalContentUri { get; set; }
}
