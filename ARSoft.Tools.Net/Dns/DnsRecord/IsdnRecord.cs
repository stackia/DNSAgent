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
	///   <para>ISDN address</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc1183">RFC 1183</see>
	///   </para>
	/// </summary>
	public class IsdnRecord : DnsRecordBase
	{
		/// <summary>
		///   ISDN number
		/// </summary>
		public string IsdnAddress { get; private set; }

		/// <summary>
		///   Sub address
		/// </summary>
		public string SubAddress { get; private set; }

		internal IsdnRecord() {}

		/// <summary>
		///   Creates a new instance of the IsdnRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="isdnAddress"> ISDN number </param>
		public IsdnRecord(string name, int timeToLive, string isdnAddress)
			: this(name, timeToLive, isdnAddress, String.Empty) {}

		/// <summary>
		///   Creates a new instance of the IsdnRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="isdnAddress"> ISDN number </param>
		/// <param name="subAddress"> Sub address </param>
		public IsdnRecord(string name, int timeToLive, string isdnAddress, string subAddress)
			: base(name, RecordType.Isdn, RecordClass.INet, timeToLive)
		{
			IsdnAddress = isdnAddress ?? String.Empty;
			SubAddress = subAddress ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			int endPosition = currentPosition + length;

			IsdnAddress = DnsMessageBase.ParseText(resultData, ref currentPosition);
			SubAddress = (currentPosition < endPosition) ? DnsMessageBase.ParseText(resultData, ref currentPosition) : String.Empty;
		}

		internal override string RecordDataToString()
		{
			return IsdnAddress
			       + (String.IsNullOrEmpty(SubAddress) ? String.Empty : " " + SubAddress);
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 2 + IsdnAddress.Length + SubAddress.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, IsdnAddress);
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, SubAddress);
		}
	}
}