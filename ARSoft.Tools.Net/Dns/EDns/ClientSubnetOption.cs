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
using System.Net.Sockets;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>EDNS0 Client Subnet Option</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/draft-vandergaast-edns-client-subnet-02">draft-vandergaast-edns-client-subnet</see>
	///   </para>
	/// </summary>
	public class ClientSubnetOption : EDnsOptionBase
	{
		/// <summary>
		///   The address family
		/// </summary>
		public AddressFamily Family
		{
			get { return Address.AddressFamily; }
		}

		/// <summary>
		///   The source subnet mask
		/// </summary>
		public byte SourceNetmask { get; private set; }

		/// <summary>
		///   The scope subnet mask
		/// </summary>
		public byte ScopeNetmask { get; private set; }

		/// <summary>
		///   The address
		/// </summary>
		public IPAddress Address { get; private set; }

		internal ClientSubnetOption()
			: base(EDnsOptionType.ClientSubnet) { }

		/// <summary>
		///   Creates a new instance of the OwnerOption class
		/// </summary>
		/// <param name="sourceNetmask"> The source subnet mask </param>
		/// <param name="address"> The address </param>
		public ClientSubnetOption(byte sourceNetmask, IPAddress address)
			: this(sourceNetmask, 0, address) { }

		/// <summary>
		///   Creates a new instance of the OwnerOption class
		/// </summary>
		/// <param name="sourceNetmask"> The source subnet mask </param>
		/// <param name="scopeNetmask"> The scope subnet mask </param>
		/// <param name="address"> The address </param>
		public ClientSubnetOption(byte sourceNetmask, byte scopeNetmask, IPAddress address)
			: this()
		{
			SourceNetmask = sourceNetmask;
			ScopeNetmask = scopeNetmask;
			Address = address;
		}

		internal override void ParseData(byte[] resultData, int startPosition, int length)
		{
			ushort family = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			SourceNetmask = resultData[startPosition++];
			ScopeNetmask = resultData[startPosition++];

			byte[] addressData = new byte[family == 1 ? 4 : 16];
			Buffer.BlockCopy(resultData, startPosition, addressData, 0, GetAddressLength());

			Address = new IPAddress(addressData);
		}

		internal override ushort DataLength
		{
			get { return (ushort) (4 + GetAddressLength()); }
		}

		internal override void EncodeData(byte[] messageData, ref int currentPosition)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) (Family == AddressFamily.InterNetwork ? 1 : 2));
			messageData[currentPosition++] = SourceNetmask;
			messageData[currentPosition++] = ScopeNetmask;

			byte[] data = Address.GetAddressBytes();
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, data, GetAddressLength());
		}

		private int GetAddressLength()
		{
			return (int) Math.Ceiling(SourceNetmask / 8d);
		}
	}
}