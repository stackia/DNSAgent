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
	///   <para>Well known services record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
	///   </para>
	/// </summary>
	public class WksRecord : DnsRecordBase
	{
		/// <summary>
		///   IP address of the host
		/// </summary>
		public IPAddress Address { get; private set; }

		/// <summary>
		///   Type of the protocol
		/// </summary>
		public ProtocolType Protocol { get; private set; }

		/// <summary>
		///   List of ports which are supported by the host
		/// </summary>
		public List<ushort> Ports { get; private set; }

		internal WksRecord() {}

		/// <summary>
		///   Creates a new instance of the WksRecord class
		/// </summary>
		/// <param name="name"> Name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="address"> IP address of the host </param>
		/// <param name="protocol"> Type of the protocol </param>
		/// <param name="ports"> List of ports which are supported by the host </param>
		public WksRecord(string name, int timeToLive, IPAddress address, ProtocolType protocol, List<ushort> ports)
			: base(name, RecordType.Wks, RecordClass.INet, timeToLive)
		{
			Address = address ?? IPAddress.None;
			Protocol = protocol;
			Ports = ports ?? new List<ushort>();
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			int endPosition = currentPosition + length;

			Address = new IPAddress(DnsMessageBase.ParseByteData(resultData, ref currentPosition, 4));
			Protocol = (ProtocolType) resultData[currentPosition++];
			Ports = new List<ushort>();

			int octetNumber = 0;
			while (currentPosition < endPosition)
			{
				byte octet = resultData[currentPosition++];

				for (int bit = 0; bit < 8; bit++)
				{
					if ((octet & (1 << Math.Abs(bit - 7))) != 0)
					{
						Ports.Add((ushort) (octetNumber * 8 + bit));
					}
				}

				octetNumber++;
			}
		}

		internal override string RecordDataToString()
		{
			return Address
			       + " " + (byte) Protocol
			       + " " + String.Join(" ", Ports.ConvertAll(port => port.ToString()).ToArray());
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 5 + Ports.Max() / 8 + 1; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Address.GetAddressBytes());
			messageData[currentPosition++] = (byte) Protocol;

			foreach (ushort port in Ports)
			{
				int octetPosition = port / 8 + currentPosition;
				int bitPos = port % 8;
				byte octet = messageData[octetPosition];
				octet |= (byte) (1 << Math.Abs(bitPos - 7));
				messageData[octetPosition] = octet;
			}
			currentPosition += Ports.Max() / 8 + 1;
		}
	}
}