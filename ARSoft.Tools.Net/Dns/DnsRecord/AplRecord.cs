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
	///   <para>Address prefixes record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc3123">RFC 3123</see>
	///   </para>
	/// </summary>
	public class AplRecord : DnsRecordBase
	{
		internal enum Family : ushort
		{
			/// <summary>
			///   <para>IPv4</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc3123">RFC 3123</see>
			///   </para>
			/// </summary>
			IpV4 = 1,

			/// <summary>
			///   <para>IPv6</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc3123">RFC 3123</see>
			///   </para>
			/// </summary>
			IpV6 = 2,
		}

		/// <summary>
		///   Represents an address prefix
		/// </summary>
		public class AddressPrefix
		{
			/// <summary>
			///   Is negated prefix
			/// </summary>
			public bool IsNegated { get; private set; }

			/// <summary>
			///   Address familiy
			/// </summary>
			internal Family AddressFamily { get; private set; }

			/// <summary>
			///   Network address
			/// </summary>
			public IPAddress Address { get; private set; }

			/// <summary>
			///   Prefix of the network
			/// </summary>
			public byte Prefix { get; private set; }

			/// <summary>
			///   Creates a new instance of the AddressPrefix class
			/// </summary>
			/// <param name="isNegated"> Is negated prefix </param>
			/// <param name="address"> Network address </param>
			/// <param name="prefix"> Prefix of the network </param>
			public AddressPrefix(bool isNegated, IPAddress address, byte prefix)
			{
				IsNegated = isNegated;
				AddressFamily = (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork) ? Family.IpV4 : Family.IpV6;
				Address = address;
				Prefix = prefix;
			}

			/// <summary>
			///   Returns the textual representation of an address prefix
			/// </summary>
			/// <returns> The textual representation </returns>
			public override string ToString()
			{
				return (IsNegated ? "!" : "")
				       + (ushort) AddressFamily
				       + ":" + Address
				       + "/" + Prefix;
			}
		}

		/// <summary>
		///   List of address prefixes covered by this record
		/// </summary>
		public List<AddressPrefix> Prefixes { get; private set; }

		internal AplRecord() {}

		/// <summary>
		///   Creates a new instance of the AplRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="prefixes"> List of address prefixes covered by this record </param>
		public AplRecord(string name, int timeToLive, List<AddressPrefix> prefixes)
			: base(name, RecordType.Apl, RecordClass.INet, timeToLive)
		{
			Prefixes = prefixes ?? new List<AddressPrefix>();
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			int endPosition = currentPosition + length;

			Prefixes = new List<AddressPrefix>();
			while (currentPosition < endPosition)
			{
				Family family = (Family) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
				byte prefix = resultData[currentPosition++];

				byte addressLength = resultData[currentPosition++];
				bool isNegated = false;
				if (addressLength > 127)
				{
					isNegated = true;
					addressLength -= 128;
				}

				byte[] addressData = new byte[(family == Family.IpV4) ? 4 : 16];
				Buffer.BlockCopy(resultData, currentPosition, addressData, 0, addressLength);
				currentPosition += addressLength;

				Prefixes.Add(new AddressPrefix(isNegated, new IPAddress(addressData), prefix));
			}
		}

		internal override string RecordDataToString()
		{
			return String.Join(" ", Prefixes.ConvertAll(p => p.ToString()).ToArray());
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return Prefixes.Count * 20; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			foreach (AddressPrefix addressPrefix in Prefixes)
			{
				DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) addressPrefix.AddressFamily);
				messageData[currentPosition++] = addressPrefix.Prefix;

				// no increment of position pointer, just set 1 bit
				if (addressPrefix.IsNegated)
					messageData[currentPosition] = 128;

				byte[] addressData = addressPrefix.Address.GetNetworkAddress(addressPrefix.Prefix).GetAddressBytes();
				int length = addressData.Length;
				for (; length > 0; length--)
				{
					if (addressData[length - 1] != 0)
						break;
				}
				messageData[currentPosition++] |= (byte) length;
				DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, addressData, length);
			}
		}
	}
}