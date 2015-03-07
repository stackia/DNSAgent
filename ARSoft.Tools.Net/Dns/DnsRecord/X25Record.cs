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
	///   <para>X.25 PSDN address record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc1183">RFC 1183</see>
	///   </para>
	/// </summary>
	public class X25Record : DnsRecordBase
	{
		/// <summary>
		///   PSDN (Public Switched Data Network) address
		/// </summary>
		public string X25Address { get; protected set; }

		internal X25Record() {}

		/// <summary>
		///   Creates a new instance of the X25Record class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="x25Address"> PSDN (Public Switched Data Network) address </param>
		public X25Record(string name, int timeToLive, string x25Address)
			: base(name, RecordType.X25, RecordClass.INet, timeToLive)
		{
			X25Address = x25Address ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			X25Address += DnsMessageBase.ParseText(resultData, ref startPosition);
		}

		internal override string RecordDataToString()
		{
			return X25Address;
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 1 + X25Address.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, X25Address);
		}
	}
}