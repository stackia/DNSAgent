#region Copyright and License
// Copyright 2010..2014 Alexander Reinert
// 
// This file is part of the ARSoft.Tools.Net - C# DNS client/server and SPF Library (http://arsofttoolsnet.codeplex.com/)
// 
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
// 
//   http://www.apache.org/licenses/LICENSE-2.0
// 
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#endregion

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Transaction key</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc2930">RFC 2930</see>
	///   </para>
	/// </summary>
	public class TKeyRecord : DnsRecordBase
	{
		/// <summary>
		///   Mode of transaction
		/// </summary>
		public enum TKeyMode : ushort
		{
			/// <summary>
			///   <para>Server assignment</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2930">RFC 2930</see>
			///   </para>
			/// </summary>
			ServerAssignment = 1, // RFC2930

			/// <summary>
			///   <para>Diffie-Hellman exchange</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2930">RFC 2930</see>
			///   </para>
			/// </summary>
			DiffieHellmanExchange = 2, // RFC2930

			/// <summary>
			///   <para>GSS-API negotiation</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2930">RFC 2930</see>
			///   </para>
			/// </summary>
			GssNegotiation = 3, // RFC2930

			/// <summary>
			///   <para>Resolver assignment</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2930">RFC 2930</see>
			///   </para>
			/// </summary>
			ResolverAssignment = 4, // RFC2930

			/// <summary>
			///   <para>Key deletion</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2930">RFC 2930</see>
			///   </para>
			/// </summary>
			KeyDeletion = 5, // RFC2930
		}

		/// <summary>
		///   Algorithm of the key
		/// </summary>
		public TSigAlgorithm Algorithm { get; private set; }

		/// <summary>
		///   Date from which the key is valid
		/// </summary>
		public DateTime Inception { get; private set; }

		/// <summary>
		///   Date to which the key is valid
		/// </summary>
		public DateTime Expiration { get; private set; }

		/// <summary>
		///   Mode of transaction
		/// </summary>
		public TKeyMode Mode { get; private set; }

		/// <summary>
		///   Error field
		/// </summary>
		public ReturnCode Error { get; private set; }

		/// <summary>
		///   Binary data of the key
		/// </summary>
		public byte[] Key { get; private set; }

		/// <summary>
		///   Binary other data
		/// </summary>
		public byte[] OtherData { get; private set; }

		internal TKeyRecord() {}

		/// <summary>
		///   Creates a new instance of the TKeyRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="algorithm"> Algorithm of the key </param>
		/// <param name="inception"> Date from which the key is valid </param>
		/// <param name="expiration"> Date to which the key is valid </param>
		/// <param name="mode"> Mode of transaction </param>
		/// <param name="error"> Error field </param>
		/// <param name="key"> Binary data of the key </param>
		/// <param name="otherData"> Binary other data </param>
		public TKeyRecord(string name, TSigAlgorithm algorithm, DateTime inception, DateTime expiration, TKeyMode mode, ReturnCode error, byte[] key, byte[] otherData)
			: base(name, RecordType.TKey, RecordClass.Any, 0)
		{
			Algorithm = algorithm;
			Inception = inception;
			Expiration = expiration;
			Mode = mode;
			Error = error;
			Key = key ?? new byte[] { };
			OtherData = otherData ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Algorithm = TSigAlgorithmHelper.GetAlgorithmByName(DnsMessageBase.ParseDomainName(resultData, ref startPosition));
			Inception = ParseDateTime(resultData, ref startPosition);
			Expiration = ParseDateTime(resultData, ref startPosition);
			Mode = (TKeyMode) DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Error = (ReturnCode) DnsMessageBase.ParseUShort(resultData, ref startPosition);
			int keyLength = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Key = DnsMessageBase.ParseByteData(resultData, ref startPosition, keyLength);
			int otherDataLength = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			OtherData = DnsMessageBase.ParseByteData(resultData, ref startPosition, otherDataLength);
		}

		internal override string RecordDataToString()
		{
			return TSigAlgorithmHelper.GetDomainName(Algorithm)
			       + " " + (int) (Inception - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
			       + " " + (int) (Expiration - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
			       + " " + (ushort) Mode
			       + " " + (ushort) Error
			       + " " + Key.ToBase64String()
			       + " " + OtherData.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 18 + TSigAlgorithmHelper.GetDomainName(Algorithm).Length + Key.Length + OtherData.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, TSigAlgorithmHelper.GetDomainName(Algorithm), false, domainNames);
			EncodeDateTime(messageData, ref currentPosition, Inception);
			EncodeDateTime(messageData, ref currentPosition, Expiration);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Mode);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Error);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Key.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Key);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) OtherData.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, OtherData);
		}

		internal static void EncodeDateTime(byte[] buffer, ref int currentPosition, DateTime value)
		{
			int timeStamp = (int) (value.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
			DnsMessageBase.EncodeInt(buffer, ref currentPosition, timeStamp);
		}

		private static DateTime ParseDateTime(byte[] buffer, ref int currentPosition)
		{
			int timeStamp = DnsMessageBase.ParseInt(buffer, ref currentPosition);
			return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(timeStamp).ToLocalTime();
		}
	}
}