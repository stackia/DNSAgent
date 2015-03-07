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
using System.Net;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Host address record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
	///   </para>
	/// </summary>
	public class ARecord : DnsRecordBase, IAddressRecord
	{
		/// <summary>
		///   IP address of the host
		/// </summary>
		public IPAddress Address { get; private set; }

		internal ARecord() {}

		/// <summary>
		///   Creates a new instance of the ARecord class
		/// </summary>
		/// <param name="name"> Domain name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="address"> IP address of the host </param>
		public ARecord(string name, int timeToLive, IPAddress address)
			: base(name, RecordType.A, RecordClass.INet, timeToLive)
		{
			Address = address ?? IPAddress.None;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Address = new IPAddress(DnsMessageBase.ParseByteData(resultData, ref startPosition, 4));
		}

		internal override string RecordDataToString()
		{
			return Address.ToString();
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 4; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Address.GetAddressBytes());
		}
	}
}