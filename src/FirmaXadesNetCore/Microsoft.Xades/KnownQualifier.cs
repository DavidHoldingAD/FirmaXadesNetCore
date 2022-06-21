// Identifier.cs
//
// XAdES Starter Kit for Microsoft .NET 3.5 (and above)
// 2010 Microsoft France
//
// Originally published under the CECILL-B Free Software license agreement,
// modified by Dpto. de Nuevas Tecnologнas de la Direcciуn General de Urbanismo del Ayto. de Cartagena
// and published under the GNU Lesser General Public License version 3.
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

namespace Microsoft.Xades;

/// <summary>
/// Possible values for Qualifier
/// </summary>
public enum KnownQualifier
{
	/// <summary>
	/// Value has not been set
	/// </summary>
	Uninitalized,

	/// <summary>
	/// OID encoded as Uniform Resource Identifier (URI).
	/// </summary>
	OIDAsURI,

	/// <summary>
	/// OID encoded as Uniform Resource Name (URN)
	/// </summary>
	OIDAsURN,
}
