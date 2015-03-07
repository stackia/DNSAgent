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
	///   A single entry of the Question section of a dns query
	/// </summary>
	public class DnsQuestion : DnsMessageEntryBase
	{
		/// <summary>
		///   Creates a new instance of the DnsQuestion class
		/// </summary>
		/// <param name="name"> Domain name </param>
		/// <param name="recordType"> Record type </param>
		/// <param name="recordClass"> Record class </param>
		public DnsQuestion(string name, RecordType recordType, RecordClass recordClass)
		{
			Name = name ?? String.Empty;
			RecordType = recordType;
			RecordClass = recordClass;
		}

		internal DnsQuestion() {}

		internal override int MaximumLength
		{
			get { return Name.Length + 6; }
		}

		internal void Encode(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames, bool useCompressionMutation)
		{
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Name, true, useCompressionMutation, domainNames);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordType);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) RecordClass);
		}
	}
}