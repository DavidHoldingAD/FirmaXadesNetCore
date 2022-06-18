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

using System.Net;
using System.Text;
using FirmaXadesNetCore.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Tsp;

namespace FirmaXadesNetCore.Clients;

public sealed class TimeStampClient : ITimeStampClient
{
	private readonly string _url;
	private readonly string _user;
	private readonly string _password;

	public TimeStampClient(string url)
	{
		_url = url ?? throw new ArgumentNullException(nameof(url));
	}

	public TimeStampClient(string url, string user, string password)
		: this(url)
	{
		_user = user ?? throw new ArgumentNullException(nameof(user));
		_password = password ?? throw new ArgumentNullException(nameof(password));
	}

	#region ITimeStampClient Members

	/// <inheritdoc/>
	public byte[] GetTimeStamp(byte[] hash, DigestMethod digestMethod, bool certReq)
	{
		if (hash is null)
		{
			throw new ArgumentNullException(nameof(hash));
		}

		if (digestMethod is null)
		{
			throw new ArgumentNullException(nameof(digestMethod));
		}

		var timeStampRequestGenerator = new TimeStampRequestGenerator();
		timeStampRequestGenerator.SetCertReq(certReq);

		TimeStampRequest timeStampRequest = timeStampRequestGenerator
			.Generate(digestMethod.Oid, hash, BigInteger.ValueOf(DateTime.Now.Ticks));
		byte[] timeStampRequestBytes = timeStampRequest.GetEncoded();

		var request = (HttpWebRequest)WebRequest.Create(_url);
		request.Method = "POST";
		request.ContentType = "application/timestamp-query";
		request.ContentLength = timeStampRequestBytes.Length;

		if (!string.IsNullOrEmpty(_user)
			&& !string.IsNullOrEmpty(_password))
		{
			string basicAuthenticationValue = Convert.ToBase64String(
				Encoding.Default.GetBytes($"{_user}:{_password}"),
				Base64FormattingOptions.None);

			request.Headers["Authorization"] = $"Basic {basicAuthenticationValue}";
		}

		using Stream requestStream = request.GetRequestStream();
		requestStream.Write(timeStampRequestBytes, 0, timeStampRequestBytes.Length);
		requestStream.Close();

		var response = (HttpWebResponse)request.GetResponse();
		if (response.StatusCode != HttpStatusCode.OK)
		{
			throw new Exception("The server has returned an invalid response.");
		}
		else
		{
			using Stream responseStream = new BufferedStream(response.GetResponseStream());
			var timeStampResponse = new TimeStampResponse(responseStream);
			responseStream.Close();

			timeStampResponse.Validate(timeStampRequest);

			if (timeStampResponse.TimeStampToken == null)
			{
				throw new Exception("The server has not returned any timestamp.");
			}

			return timeStampResponse.TimeStampToken.GetEncoded();
		}
	}

	#endregion
}
