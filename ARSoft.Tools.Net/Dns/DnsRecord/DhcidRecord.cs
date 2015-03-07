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
	///   <para>Dynamic Host Configuration Protocol (DHCP) Information record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc4701">RFC 4701</see>
	///   </para>
	/// </summary>
	public class DhcidRecord : DnsRecordBase
	{
		/// <summary>
		///   Record data
		/// </summary>
		public byte[] RecordData { get; private set; }

		internal DhcidRecord() {}

		/// <summary>
		///   Creates a new instance of the DhcidRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="recordData"> Record data </param>
		public DhcidRecord(string name, int timeToLive, byte[] recordData)
			: base(name, RecordType.Dhcid, RecordClass.INet, timeToLive)
		{
			RecordData = recordData ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			RecordData = DnsMessageBase.ParseByteData(resultData, ref startPosition, length);
		}

		internal override string RecordDataToString()
		{
			return RecordData.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return RecordData.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, RecordData);
		}
	}
}