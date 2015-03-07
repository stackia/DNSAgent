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
	///   <para>Key exchanger record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc2230">RFC 2230</see>
	///   </para>
	/// </summary>
	public class KxRecord : DnsRecordBase
	{
		/// <summary>
		///   Preference of the record
		/// </summary>
		public ushort Preference { get; private set; }

		/// <summary>
		///   Domain name of the exchange host
		/// </summary>
		public string Exchanger { get; private set; }

		internal KxRecord() {}

		/// <summary>
		///   Creates a new instance of the KxRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="preference"> Preference of the record </param>
		/// <param name="exchanger"> Domain name of the exchange host </param>
		public KxRecord(string name, int timeToLive, ushort preference, string exchanger)
			: base(name, RecordType.Kx, RecordClass.INet, timeToLive)
		{
			Preference = preference;
			Exchanger = exchanger ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Preference = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Exchanger = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
		}

		internal override string RecordDataToString()
		{
			return Preference
			       + " " + Exchanger;
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return Exchanger.Length + 4; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Exchanger, true, domainNames);
		}
	}
}