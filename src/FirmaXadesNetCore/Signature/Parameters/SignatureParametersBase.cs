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

using FirmaXadesNetCore.Crypto;

namespace FirmaXadesNetCore.Signature.Parameters;

public abstract class SignatureParametersBase
{
	public SignatureMethod SignatureMethod { get; set; } = SignatureMethod.RSAwithSHA256;

	public DigestMethod DigestMethod { get; set; } = DigestMethod.SHA256;

	public DateTime? SigningDate { get; set; }

	public SignerRole SignerRole { get; set; }

	public List<SignatureCommitment> SignatureCommitments { get; } = new();

	public SignatureProductionPlace SignatureProductionPlace { get; set; }

	public List<SignatureXPathExpression> XPathTransformations { get; } = new();

	public SignaturePolicyInfo SignaturePolicyInfo { get; set; }

	public SignatureXPathExpression SignatureDestination { get; set; }

	public SignaturePackaging SignaturePackaging { get; set; }

	public DataFormat DataFormat { get; set; }

	public string ElementIdToSign { get; set; }

	public string ExternalContentUri { get; set; }
}
