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
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;

namespace ARSoft.Tools.Net
{
	/// <summary>
	///   Extension class for the <see cref="IPAddress" /> class
	/// </summary>
	public static class IPAddressExtension
	{
		/// <summary>
		///   Reverses the order of the bytes of an IPAddress
		/// </summary>
		/// <param name="ipAddress"> Instance of the IPAddress, that should be reversed </param>
		/// <returns> New instance of IPAddress with reversed address </returns>
		public static IPAddress Reverse(this IPAddress ipAddress)
		{
			if (ipAddress == null)
				throw new ArgumentNullException("ipAddress");

			byte[] addressBytes = ipAddress.GetAddressBytes();
			byte[] res = new byte[addressBytes.Length];

			for (int i = 0; i < res.Length; i++)
			{
				res[i] = addressBytes[addressBytes.Length - i - 1];
			}

			return new IPAddress(res);
		}

		/// <summary>
		///   Gets the network address for a specified IPAddress and netmask
		/// </summary>
		/// <param name="ipAddress"> IPAddress, for that the network address should be returned </param>
		/// <param name="netmask"> Netmask, that should be used </param>
		/// <returns> New instance of IPAddress with the network address assigend </returns>
		public static IPAddress GetNetworkAddress(this IPAddress ipAddress, IPAddress netmask)
		{
			if (ipAddress == null)
				throw new ArgumentNullException("ipAddress");

			if (netmask == null)
				throw new ArgumentNullException("netMask");

			if (ipAddress.AddressFamily != netmask.AddressFamily)
				throw new ArgumentOutOfRangeException("netmask", "Protocoll version of ipAddress and netmask do not match");

			byte[] resultBytes = ipAddress.GetAddressBytes();
			byte[] ipAddressBytes = ipAddress.GetAddressBytes();
			byte[] netmaskBytes = netmask.GetAddressBytes();

			for (int i = 0; i < netmaskBytes.Length; i++)
			{
				resultBytes[i] = (byte) (ipAddressBytes[i] & netmaskBytes[i]);
			}

			return new IPAddress(resultBytes);
		}

		/// <summary>
		///   Gets the network address for a specified IPAddress and netmask
		/// </summary>
		/// <param name="ipAddress"> IPAddress, for that the network address should be returned </param>
		/// <param name="netmask"> Netmask in CIDR format </param>
		/// <returns> New instance of IPAddress with the network address assigend </returns>
		public static IPAddress GetNetworkAddress(this IPAddress ipAddress, int netmask)
		{
			if (ipAddress == null)
				throw new ArgumentNullException("ipAddress");

			if ((ipAddress.AddressFamily == AddressFamily.InterNetwork) && ((netmask < 0) || (netmask > 32)))
				throw new ArgumentException("Netmask have to be in range of 0 to 32 on IPv4 addresses", "netmask");

			if ((ipAddress.AddressFamily == AddressFamily.InterNetworkV6) && ((netmask < 0) || (netmask > 128)))
				throw new ArgumentException("Netmask have to be in range of 0 to 128 on IPv6 addresses", "netmask");

			byte[] ipAddressBytes = ipAddress.GetAddressBytes();

			for (int i = 0; i < ipAddressBytes.Length; i++)
			{
				if (netmask >= 8)
				{
					netmask -= 8;
				}
				else
				{
					if (BitConverter.IsLittleEndian)
					{
						ipAddressBytes[i] &= ReverseBitOrder((byte) ~(255 << netmask));
					}
					netmask = 0;
				}
			}

			return new IPAddress(ipAddressBytes);
		}

		/// <summary>
		///   Returns the reverse lookup address of an IPAddress
		/// </summary>
		/// <param name="ipAddress"> Instance of the IPAddress, that should be used </param>
		/// <returns> A string with the reverse lookup address </returns>
		public static string GetReverseLookupAddress(this IPAddress ipAddress)
		{
			if (ipAddress == null)
				throw new ArgumentNullException("ipAddress");

			StringBuilder res = new StringBuilder();

			byte[] addressBytes = ipAddress.GetAddressBytes();

			if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
			{
				for (int i = addressBytes.Length - 1; i >= 0; i--)
				{
					res.Append(addressBytes[i]);
					res.Append(".");
				}
				res.Append("in-addr.arpa");
			}
			else
			{
				for (int i = addressBytes.Length - 1; i >= 0; i--)
				{
					string hex = addressBytes[i].ToString("x2");
					res.Append(hex[1]);
					res.Append(".");
					res.Append(hex[0]);
					res.Append(".");
				}

				res.Append("ip6.arpa");
			}

			return res.ToString();
		}

		private static readonly IPAddress _ipv4MulticastNetworkAddress = IPAddress.Parse("224.0.0.0");
		private static readonly IPAddress _ipv6MulticastNetworkAddress = IPAddress.Parse("FF00::");

		/// <summary>
		///   Returns a value indicating whether a ip address is a multicast address
		/// </summary>
		/// <param name="ipAddress"> Instance of the IPAddress, that should be used </param>
		/// <returns> true, if the given address is a multicast address; otherwise, false </returns>
		public static bool IsMulticast(this IPAddress ipAddress)
		{
			if (ipAddress == null)
				throw new ArgumentNullException("ipAddress");

			if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
			{
				return ipAddress.GetNetworkAddress(4).Equals(_ipv4MulticastNetworkAddress);
			}
			else
			{
				return ipAddress.GetNetworkAddress(8).Equals(_ipv6MulticastNetworkAddress);
			}
		}

		/// <summary>
		///   Returns the index for the interface which has the ip address assigned
		/// </summary>
		/// <param name="ipAddress"> The ip address to look for </param>
		/// <returns> The index for the interface which has the ip address assigned </returns>
		public static int GetInterfaceIndex(this IPAddress ipAddress)
		{
			if (ipAddress == null)
				throw new ArgumentNullException("ipAddress");

			var interfaceProperty = NetworkInterface.GetAllNetworkInterfaces().Select(n => n.GetIPProperties()).FirstOrDefault(p => p.UnicastAddresses.Any(a => a.Address.Equals(ipAddress)));

			if (interfaceProperty != null)
			{
				if (ipAddress.AddressFamily == AddressFamily.InterNetwork)
				{
					var property = interfaceProperty.GetIPv4Properties();
					if (property != null)
						return property.Index;
				}
				else
				{
					var property = interfaceProperty.GetIPv6Properties();
					if (property != null)
						return property.Index;
				}
			}

			throw new ArgumentOutOfRangeException("ipAddress", "The given ip address is not configured on the local system");
		}

		private static byte ReverseBitOrder(byte value)
		{
			byte result = 0;

			for (int i = 0; i < 8; i++)
			{
				result |= (byte) ((((1 << i) & value) >> i) << (7 - i));
			}

			return result;
		}
	}
}