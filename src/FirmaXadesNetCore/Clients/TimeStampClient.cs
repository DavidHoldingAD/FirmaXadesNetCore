// --------------------------------------------------------------------------------------------------------------------
// TimeStampClient.cs
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

using System.Net.Http.Headers;
using System.Text;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;

namespace FirmaXadesNetCore.Clients;

/// <summary>
/// Represents a timestamp client.
/// </summary>
public sealed class TimeStampClient : ITimestampClient, IDisposable
{
	private readonly HttpClient _httpClient;
	private bool _disposed;

	/// <summary>
	/// Initializes a new instance of <see cref="TimeStampClient"/> class.
	/// </summary>
	/// <param name="uri">the URI</param>
	public TimeStampClient(Uri uri)
	{
		if (uri is null)
		{
			throw new ArgumentNullException(nameof(uri));
		}

		_httpClient = new HttpClient
		{
			BaseAddress = uri,
		};
	}

	/// <summary>
	/// Initializes a new instance of <see cref="TimeStampClient"/> class.
	/// </summary>
	/// <param name="uri">the URI</param>
	/// <param name="username">the username</param>
	/// <param name="password">the password</param>
	public TimeStampClient(Uri uri, string username, string password)
		: this(uri)
	{
		if (uri is null)
		{
			throw new ArgumentNullException(nameof(uri));
		}

		if (username is null)
		{
			throw new ArgumentNullException(nameof(username));
		}

		if (password is null)
		{
			throw new ArgumentNullException(nameof(password));
		}

		byte[] basicAuthenticationBytes = Encoding.Default.GetBytes($"{username}:{password}");
		string basicAuthenticationBase64 = Convert.ToBase64String(basicAuthenticationBytes, Base64FormattingOptions.None);

		_httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", basicAuthenticationBase64);
	}

	#region ITimeStampClient Members

	/// <inheritdoc/>
	public async Task<byte[]> GetTimeStampAsync(byte[] hashValue,
		DigestMethod digestMethod,
		bool requestSignerCertificates,
		CancellationToken cancellationToken)
	{
		if (hashValue is null)
		{
			throw new ArgumentNullException(nameof(hashValue));
		}

		if (digestMethod is null)
		{
			throw new ArgumentNullException(nameof(digestMethod));
		}

		var timeStampRequestGenerator = new TimeStampRequestGenerator();
		timeStampRequestGenerator.SetCertReq(requestSignerCertificates);

		TimeStampRequest timeStampRequest = timeStampRequestGenerator
			.Generate(digestMethod.Oid, hashValue, BigInteger.ValueOf(DateTime.Now.Ticks));
		byte[] timeStampRequestBytes = timeStampRequest.GetEncoded();

		using var requestContent = new ByteArrayContent(timeStampRequestBytes);
		requestContent.Headers.ContentType = new MediaTypeHeaderValue("application/timestamp-query");
		requestContent.Headers.ContentLength = timeStampRequestBytes.Length;

		using HttpResponseMessage response = await _httpClient
			.PostAsync(string.Empty, requestContent, cancellationToken)
			.ConfigureAwait(continueOnCapturedContext: false);

		response.EnsureSuccessStatusCode();

		using Stream responseStream = await response.Content
			.ReadAsStreamAsync(cancellationToken)
			.ConfigureAwait(continueOnCapturedContext: false);
		using Stream bufferedResponseStream = new BufferedStream(responseStream);

		var timeStampResponse = new TimeStampResponse(bufferedResponseStream);
		timeStampResponse.Validate(timeStampRequest);

		if (timeStampResponse.TimeStampToken is null)
		{
			throw new Exception("The server has not returned any timestamp.");
		}

		return timeStampResponse.TimeStampToken.GetEncoded();
	}

	#endregion

	#region IDisposable Members

	/// <inheritdoc/>
	public void Dispose()
	{
		Dispose(disposing: true);

		GC.SuppressFinalize(this);
	}

	private void Dispose(bool disposing)
	{
		if (_disposed)
		{
			return;
		}

		if (disposing)
		{
			_httpClient.Dispose();
		}

		_disposed = true;
	}

	#endregion
}
