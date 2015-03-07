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
	///   <para>Naming authority pointer record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc2915">RFC 2915</see>
	///     ,
	///     <see cref="!:http://tools.ietf.org/html/rfc2168">RFC 2168</see>
	///     and
	///     <see cref="!:http://tools.ietf.org/html/rfc3403">RFC 3403</see>
	///   </para>
	/// </summary>
	public class NaptrRecord : DnsRecordBase
	{
		/// <summary>
		///   Order of the record
		/// </summary>
		public ushort Order { get; private set; }

		/// <summary>
		///   Preference of record with same order
		/// </summary>
		public ushort Preference { get; private set; }

		/// <summary>
		///   Flags of the record
		/// </summary>
		public string Flags { get; private set; }

		/// <summary>
		///   Available services
		/// </summary>
		public string Services { get; private set; }

		/// <summary>
		///   Substitution expression that is applied to the original string
		/// </summary>
		public string RegExp { get; private set; }

		/// <summary>
		///   The next name to query
		/// </summary>
		public string Replacement { get; private set; }

		internal NaptrRecord() {}

		/// <summary>
		///   Creates a new instance of the NaptrRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="order"> Order of the record </param>
		/// <param name="preference"> Preference of record with same order </param>
		/// <param name="flags"> Flags of the record </param>
		/// <param name="services"> Available services </param>
		/// <param name="regExp"> Substitution expression that is applied to the original string </param>
		/// <param name="replacement"> The next name to query </param>
		public NaptrRecord(string name, int timeToLive, ushort order, ushort preference, string flags, string services, string regExp, string replacement)
			: base(name, RecordType.Naptr, RecordClass.INet, timeToLive)
		{
			Order = order;
			Preference = preference;
			Flags = flags ?? String.Empty;
			Services = services ?? String.Empty;
			RegExp = regExp ?? String.Empty;
			Replacement = replacement ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Order = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Preference = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Flags = DnsMessageBase.ParseText(resultData, ref startPosition);
			Services = DnsMessageBase.ParseText(resultData, ref startPosition);
			RegExp = DnsMessageBase.ParseText(resultData, ref startPosition);
			Replacement = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
		}

		internal override string RecordDataToString()
		{
			return Order
			       + " " + Preference
			       + " \"" + Flags + "\""
			       + " \"" + Services + "\""
			       + " \"" + RegExp + "\""
			       + " \"" + Replacement + "\"";
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return Flags.Length + Services.Length + RegExp.Length + Replacement.Length + 13; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Order);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, Flags);
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, Services);
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, RegExp);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Replacement, false, domainNames);
		}
	}
}