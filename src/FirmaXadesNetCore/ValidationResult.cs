// --------------------------------------------------------------------------------------------------------------------
// ValidationResult.cs
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
/// Represents a validation result.
/// </summary>
public class ValidationResult
{
	/// <summary>
	/// Gets a flag indicating whether the result is valid or not.
	/// </summary>
	public bool IsValid { get; }

	/// <summary>
	/// Gets the message.
	/// </summary>
	public string Message { get; }

	/// <summary>
	/// Gets the exception.
	/// </summary>
	public Exception? Exception { get; }

	private ValidationResult(bool isValid, string message, Exception? exception)
	{
		IsValid = isValid;
		Message = message;
		Exception = exception;
	}

	internal static ValidationResult Invalid(string message, Exception? exception = null)
	{
		if (message is null)
		{
			throw new ArgumentNullException(nameof(message));
		}

		return new ValidationResult(false, message, exception);
	}

	internal static ValidationResult Valid(string message)
	{
		if (message is null)
		{
			throw new ArgumentNullException(nameof(message));
		}

		return new ValidationResult(true, message, exception: null);
	}
}
