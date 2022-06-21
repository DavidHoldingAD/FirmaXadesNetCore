// RSAPKCS1SHA384SignatureDescription.cs
//
// XAdES Starter Kit for Microsoft .NET 3.5 (and above)
// 2010 Microsoft France
//
// Originally published under the CECILL-B Free Software license agreement,
// modified by Dpto. de Nuevas Tecnologías de la Dirección General de Urbanismo del Ayto. de Cartagena
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

using System.Security.Cryptography;

namespace Microsoft.Xades;

/// <summary>
///     <para>
///         The RSAPKCS1SHA384SignatureDescription class provides a signature description implementation
///         for RSA-SHA256 signatures. It allows XML digital signatures to be produced using the
///         http://www.w3.org/2001/04/xmldsig-more#rsa-sha384 signature type.
///         RSAPKCS1SHA384SignatureDescription provides the same interface as other signature description
///         implementations shipped with the .NET Framework, such as
///         <see cref="RSAPKCS1SHA1SignatureDescription" />.
///     </para>
/// </summary>
internal sealed class RSAPKCS1SHA384SignatureDescription : SignatureDescription
{
	/// <summary>
	///     Construct an RSAPKCS1SHA384SignatureDescription object. The default settings for this object
	///     are:
	///     <list type="bullet">
	///         <item>Digest algorithm - <see cref="SHA384Managed" /></item>
	///         <item>Key algorithm - <see cref="RSACryptoServiceProvider" /></item>
	///         <item>Formatter algorithm - <see cref="RSAPKCS1SignatureFormatter" /></item>
	///         <item>Deformatter algorithm - <see cref="RSAPKCS1SignatureDeformatter" /></item>
	///     </list>
	/// </summary>
	public RSAPKCS1SHA384SignatureDescription()
	{
		KeyAlgorithm = typeof(RSACryptoServiceProvider).FullName;
		DigestAlgorithm = typeof(SHA384).FullName;   // Note - SHA384CryptoServiceProvider is not registered with CryptoConfig
		FormatterAlgorithm = typeof(RSAPKCS1SignatureFormatter).FullName;
		DeformatterAlgorithm = typeof(RSAPKCS1SignatureDeformatter).FullName;
	}

	public override AsymmetricSignatureDeformatter CreateDeformatter(AsymmetricAlgorithm key)
	{
		if (key == null)
		{
			throw new ArgumentNullException(nameof(key));
		}

		var deformatter = new RSAPKCS1SignatureDeformatter(key);
		deformatter.SetHashAlgorithm("SHA384");
		return deformatter;
	}

	public override AsymmetricSignatureFormatter CreateFormatter(AsymmetricAlgorithm key)
	{
		if (key == null)
		{
			throw new ArgumentNullException(nameof(key));
		}

		var formatter = new RSAPKCS1SignatureFormatter(key);
		formatter.SetHashAlgorithm("SHA384");
		return formatter;
	}
}
