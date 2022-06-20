// --------------------------------------------------------------------------------------------------------------------
// SignatureProductionPlace.cs
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

namespace FirmaXadesNetCore.Signature.Parameters;

/// <summary>
/// Represents a signature production place.
/// </summary>
public class SignatureProductionPlace
{
	/// <summary>
	/// Gets or sets the city.
	/// </summary>
	public string City { get; set; }

	/// <summary>
	/// Gets or sets the state or province.
	/// </summary>
	public string StateOrProvince { get; set; }

	/// <summary>
	/// Gets or sets the postal code.
	/// </summary>
	public string PostalCode { get; set; }

	/// <summary>
	/// Gets or sets the country name.
	/// </summary>
	public string CountryName { get; set; }
}
