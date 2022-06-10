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

namespace FirmaXadesNetCore.Signature.Parameters;

public class SignatureCommitment
{
	#region Public properties

	public SignatureCommitmentType CommitmentType { get; set; }

	public List<XmlElement> CommitmentTypeQualifiers { get; private set; }

	#endregion

	#region Constructors

	public SignatureCommitment(SignatureCommitmentType commitmentType)
	{
		CommitmentType = commitmentType;
		CommitmentTypeQualifiers = new List<XmlElement>();
	}

	#endregion

	#region Public methods

	public void AddQualifierFromXml(string xml)
	{
		var doc = new XmlDocument();
		doc.LoadXml(xml);

		CommitmentTypeQualifiers.Add(doc.DocumentElement);
	}

	#endregion

}
