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
	///   <para>Domain name pointer</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
	///   </para>
	/// </summary>
	public class PtrRecord : DnsRecordBase
	{
		/// <summary>
		///   Domain name the address points to
		/// </summary>
		public string PointerDomainName { get; private set; }

		internal PtrRecord() {}

		/// <summary>
		///   Creates a new instance of the PtrRecord class
		/// </summary>
		/// <param name="name"> Reverse name of the address </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="pointerDomainName"> Domain name the address points to </param>
		public PtrRecord(string name, int timeToLive, string pointerDomainName)
			: base(name, RecordType.Ptr, RecordClass.INet, timeToLive)
		{
			PointerDomainName = pointerDomainName ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			PointerDomainName = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
		}

		internal override string RecordDataToString()
		{
			return PointerDomainName;
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return PointerDomainName.Length + 2; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, PointerDomainName, true, domainNames);
		}
	}
}