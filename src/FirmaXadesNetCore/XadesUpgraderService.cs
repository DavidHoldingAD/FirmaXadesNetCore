// --------------------------------------------------------------------------------------------------------------------
// XadesUpgrader.cs
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

using FirmaXadesNetCore.Upgraders;
using FirmaXadesNetCore.Upgraders.Parameters;

namespace FirmaXadesNetCore;

/// <summary>
/// Represents a XAdES upgrader service.
/// </summary>
public sealed class XadesUpgraderService : IXadesUpgraderService
{
	#region IXadesUpgraderService Members

	/// <inheritdoc/>
	public void Upgrade(SignatureDocument signatureDocument, SignatureFormat toFormat, UpgradeParameters parameters)
	{
		if (signatureDocument is null)
		{
			throw new ArgumentNullException(nameof(signatureDocument));
		}

		if (parameters is null)
		{
			throw new ArgumentNullException(nameof(parameters));
		}

		SignatureDocument.CheckSignatureDocument(signatureDocument);

		IXadesUpgrader xadesUpgrader;
		if (toFormat == SignatureFormat.XadesT
			|| signatureDocument.XadesSignature!.UnsignedProperties.UnsignedSignatureProperties.SignatureTimeStampCollection.Count <= 0)
		{
			xadesUpgrader = new XadesTUpgrader();
		}
		else
		{
#if NET6_0_OR_GREATER
			xadesUpgrader = new XadesXLUpgrader();
#else
			throw new Exception($"XAdES XL is not supported on .NET 4.8 target framework.");
#endif
		}

		xadesUpgrader.Upgrade(signatureDocument, parameters);
	}

	#endregion
}
