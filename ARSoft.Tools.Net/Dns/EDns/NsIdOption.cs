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
	///   <para>Name server ID option</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc5001">RFC 5001</see>
	///   </para>
	/// </summary>
	public class NsIdOption : EDnsOptionBase
	{
		/// <summary>
		///   Binary data of the payload
		/// </summary>
		public byte[] Payload { get; private set; }

		internal NsIdOption()
			: base(EDnsOptionType.NsId) {}

		/// <summary>
		///   Creates a new instance of the NsIdOption class
		/// </summary>
		public NsIdOption(byte[] payload)
			: this()
		{
			Payload = payload;
		}

		internal override void ParseData(byte[] resultData, int startPosition, int length)
		{
			Payload = DnsMessageBase.ParseByteData(resultData, ref startPosition, length);
		}

		internal override ushort DataLength
		{
			get { return (ushort) ((Payload == null) ? 0 : Payload.Length); }
		}

		internal override void EncodeData(byte[] messageData, ref int currentPosition)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Payload);
		}
	}
}