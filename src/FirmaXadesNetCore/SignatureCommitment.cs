// --------------------------------------------------------------------------------------------------------------------
// SignatureCommitment.cs
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

using System.Xml;

namespace FirmaXadesNetCore;

/// <summary>
/// Represents a XAdES signature commitment.
/// </summary>
public class SignatureCommitment
{
	/// <summary>
	/// Gets or sets the type.
	/// </summary>
	public SignatureCommitmentType Type { get; set; }

	/// <summary>
	/// Gets or sets the type qualifiers.
	/// </summary>
	public List<XmlElement> TypeQualifiers { get; }

	/// <summary>
	/// Initializes a new instance of <see cref="SignatureCommitment"/> class.
	/// </summary>
	/// <param name="type">the type</param>
	public SignatureCommitment(SignatureCommitmentType type)
	{
		Type = type ?? throw new ArgumentNullException(nameof(type));
		TypeQualifiers = new List<XmlElement>();
	}

	/// <summary>
	/// Adds a type qualifier from the specified XML.
	/// </summary>
	/// <param name="xml">the XML</param>
	public void AddQualifierFromXml(string xml)
	{
		if (xml is null)
		{
			throw new ArgumentNullException(nameof(xml));
		}

		var document = new XmlDocument();
		document.LoadXml(xml);

		TypeQualifiers.Add(document.DocumentElement!);
	}
}
