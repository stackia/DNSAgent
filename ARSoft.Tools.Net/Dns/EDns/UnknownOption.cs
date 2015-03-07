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
	///   Unknown EDNS option
	/// </summary>
	public class UnknownOption : EDnsOptionBase
	{
		/// <summary>
		///   Binary data of the option
		/// </summary>
		public byte[] Data { get; private set; }

		internal UnknownOption(EDnsOptionType type)
			: base(type) {}

		/// <summary>
		///   Creates a new instance of the UnknownOption class
		/// </summary>
		/// <param name="type"> Type of the option </param>
		public UnknownOption(EDnsOptionType type, byte[] data)
			: this(type)
		{
			Data = data;
		}

		internal override void ParseData(byte[] resultData, int startPosition, int length)
		{
			Data = DnsMessageBase.ParseByteData(resultData, ref startPosition, length);
		}

		internal override ushort DataLength
		{
			get { return (ushort) ((Data == null) ? 0 : Data.Length); }
		}

		internal override void EncodeData(byte[] messageData, ref int currentPosition)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Data);
		}
	}
}