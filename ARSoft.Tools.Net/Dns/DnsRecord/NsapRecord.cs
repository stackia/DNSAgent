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
	///   <para>NSAP address, NSAP style A record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc1706">RFC 1706</see>
	///     and
	///     <see cref="!:http://tools.ietf.org/html/rfc1348">RFC 1348</see>
	///   </para>
	/// </summary>
	public class NsapRecord : DnsRecordBase
	{
		/// <summary>
		///   Binary encoded NSAP data
		/// </summary>
		public byte[] RecordData { get; private set; }

		internal NsapRecord() {}

		/// <summary>
		///   Creates a new instance of the NsapRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="recordData"> Binary encoded NSAP data </param>
		public NsapRecord(string name, int timeToLive, byte[] recordData)
			: base(name, RecordType.Nsap, RecordClass.INet, timeToLive)
		{
			RecordData = recordData ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			RecordData = DnsMessageBase.ParseByteData(resultData, ref startPosition, length);
		}

		internal override string RecordDataToString()
		{
			return "0x" + RecordData.ToBase16String();
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