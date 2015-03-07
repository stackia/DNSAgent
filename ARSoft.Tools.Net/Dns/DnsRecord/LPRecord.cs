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
	///   <para>LP</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc6742">RFC 6742</see>
	///   </para>
	/// </summary>
	public class LPRecord : DnsRecordBase
	{
		/// <summary>
		///   The preference
		/// </summary>
		public ushort Preference { get; private set; }

		/// <summary>
		///   The FQDN
		/// </summary>
		public string FQDN { get; private set; }

		internal LPRecord() {}

		/// <summary>
		///   Creates a new instance of the LpRecord class
		/// </summary>
		/// <param name="name"> Domain name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="preference"> The preference </param>
		/// <param name="fqdn"> The FQDN </param>
		public LPRecord(string name, int timeToLive, ushort preference, string fqdn)
			: base(name, RecordType.LP, RecordClass.INet, timeToLive)
		{
			Preference = preference;
			FQDN = fqdn;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Preference = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			FQDN = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
		}

		internal override string RecordDataToString()
		{
			return Preference + " " + FQDN;
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 4 + FQDN.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, FQDN, false, domainNames);
		}
	}
}