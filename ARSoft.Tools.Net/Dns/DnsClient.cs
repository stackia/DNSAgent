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
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using ARSoft.Tools.Net.Dns.DynamicUpdate;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Provides a client for querying dns records
	/// </summary>
	public class DnsClient : DnsClientBase
	{
		/// <summary>
		///   Returns a default instance of the DnsClient, which uses the configured dns servers of the executing computer and a query timeout of 10 seconds.
		/// </summary>
		public static DnsClient Default { get; private set; }

		static DnsClient()
		{
			Default = new DnsClient(GetDnsServers(), 10000);
		}

		/// <summary>
		///   Provides a new instance with custom dns server and query timeout
		/// </summary>
		/// <param name="dnsServer"> The IPAddress of the dns server to use </param>
		/// <param name="queryTimeout"> Query timeout in milliseconds </param>
		public DnsClient(IPAddress dnsServer, int queryTimeout)
			: this(new List<IPAddress> { dnsServer }, queryTimeout) {}

		/// <summary>
		///   Provides a new instance with custom dns servers and query timeout
		/// </summary>
		/// <param name="dnsServers"> The IPAddresses of the dns servers to use </param>
		/// <param name="queryTimeout"> Query timeout in milliseconds </param>
		public DnsClient(List<IPAddress> dnsServers, int queryTimeout)
			: base(dnsServers, queryTimeout, 53) {}

		protected override int MaximumQueryMessageSize
		{
			get { return 512; }
		}

		protected override bool AreMultipleResponsesAllowedInParallelMode
		{
			get { return false; }
		}

		/// <summary>
		///   Queries a dns server for address records.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage Resolve(string name)
		{
			return Resolve(name, RecordType.A, RecordClass.INet);
		}

		/// <summary>
		///   Queries a dns server for specified records.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Recordtype the should be queried </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage Resolve(string name, RecordType recordType)
		{
			return Resolve(name, recordType, RecordClass.INet);
		}

		/// <summary>
		///   Queries a dns server for specified records.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage Resolve(string name, RecordType recordType, RecordClass recordClass)
		{
			if (String.IsNullOrEmpty(name))
			{
				throw new ArgumentException("Name must be provided", "name");
			}

			DnsMessage message = new DnsMessage() { IsQuery = true, OperationCode = OperationCode.Query, IsRecursionDesired = true, IsEDnsEnabled = true };
			message.Questions.Add(new DnsQuestion(name, recordType, recordClass));

			return SendMessage(message);
		}

		/// <summary>
		///   Queries a dns server for specified records asynchronously.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="requestCallback">
		///   An <see cref="System.AsyncCallback" /> delegate that references the method to invoked then the operation is complete.
		/// </param>
		/// <param name="state">
		///   A user-defined object that contains information about the receive operation. This object is passed to the
		///   <paramref
		///     name="requestCallback" />
		///   delegate when the operation is complete.
		/// </param>
		/// <returns>
		///   An <see cref="System.IAsyncResult" /> IAsyncResult object that references the asynchronous receive.
		/// </returns>
		public IAsyncResult BeginResolve(string name, AsyncCallback requestCallback, object state)
		{
			return BeginResolve(name, RecordType.A, RecordClass.INet, requestCallback, state);
		}

		/// <summary>
		///   Queries a dns server for specified records asynchronously.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="requestCallback">
		///   An <see cref="System.AsyncCallback" /> delegate that references the method to invoked then the operation is complete.
		/// </param>
		/// <param name="state">
		///   A user-defined object that contains information about the receive operation. This object is passed to the
		///   <paramref
		///     name="requestCallback" />
		///   delegate when the operation is complete.
		/// </param>
		/// <returns>
		///   An <see cref="System.IAsyncResult" /> IAsyncResult object that references the asynchronous receive.
		/// </returns>
		public IAsyncResult BeginResolve(string name, RecordType recordType, AsyncCallback requestCallback, object state)
		{
			return BeginResolve(name, recordType, RecordClass.INet, requestCallback, state);
		}

		/// <summary>
		///   Queries a dns server for specified records asynchronously.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <param name="recordClass"> Class the should be queried </param>
		/// <param name="requestCallback">
		///   An <see cref="System.AsyncCallback" /> delegate that references the method to invoked then the operation is complete.
		/// </param>
		/// <param name="state">
		///   A user-defined object that contains information about the receive operation. This object is passed to the
		///   <paramref
		///     name="requestCallback" />
		///   delegate when the operation is complete.
		/// </param>
		/// <returns>
		///   An <see cref="System.IAsyncResult" /> IAsyncResult object that references the asynchronous receive.
		/// </returns>
		public IAsyncResult BeginResolve(string name, RecordType recordType, RecordClass recordClass, AsyncCallback requestCallback, object state)
		{
			if (String.IsNullOrEmpty(name))
			{
				throw new ArgumentException("Name must be provided", "name");
			}

			DnsMessage message = new DnsMessage() { IsQuery = true, OperationCode = OperationCode.Query, IsRecursionDesired = true, IsEDnsEnabled = true };
			message.Questions.Add(new DnsQuestion(name, recordType, recordClass));

			return BeginSendMessage(message, requestCallback, state);
		}

		/// <summary>
		///   Ends a pending asynchronous operation.
		/// </summary>
		/// <param name="ar">
		///   An <see cref="System.IAsyncResult" /> object returned by a call to
		///   <see
		///     cref="ARSoft.Tools.Net.Dns.DnsClient.BeginResolve" />
		///   .
		/// </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage EndResolve(IAsyncResult ar)
		{
			return EndSendMessage<DnsMessage>(ar).FirstOrDefault();
		}

		/// <summary>
		///   Send a custom message to the dns server and returns the answer.
		/// </summary>
		/// <param name="message"> Message, that should be send to the dns server </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage SendMessage(DnsMessage message)
		{
			if (message == null)
				throw new ArgumentNullException("message");

			if ((message.Questions == null) || (message.Questions.Count == 0))
				throw new ArgumentException("At least one question must be provided", "message");

			return SendMessage<DnsMessage>(message);
		}

		/// <summary>
		///   Send an dynamic update to the dns server and returns the answer.
		/// </summary>
		/// <param name="message"> Update, that should be send to the dns server </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsUpdateMessage SendUpdate(DnsUpdateMessage message)
		{
			if (message == null)
				throw new ArgumentNullException("message");

			if (String.IsNullOrEmpty(message.ZoneName))
				throw new ArgumentException("Zone name must be provided", "message");

			return SendMessage(message);
		}

		/// <summary>
		///   Send a custom message to the dns server and returns the answer asynchronously.
		/// </summary>
		/// <param name="message"> Message, that should be send to the dns server </param>
		/// <param name="requestCallback">
		///   An <see cref="System.AsyncCallback" /> delegate that references the method to invoked then the operation is complete.
		/// </param>
		/// <param name="state">
		///   A user-defined object that contains information about the receive operation. This object is passed to the
		///   <paramref
		///     name="requestCallback" />
		///   delegate when the operation is complete.
		/// </param>
		/// <returns>
		///   An <see cref="System.IAsyncResult" /> IAsyncResult object that references the asynchronous receive.
		/// </returns>
		public IAsyncResult BeginSendMessage(DnsMessage message, AsyncCallback requestCallback, object state)
		{
			if (message == null)
				throw new ArgumentNullException("message");

			if ((message.Questions == null) || (message.Questions.Count == 0))
				throw new ArgumentException("At least one question must be provided", "message");

			return BeginSendMessage<DnsMessage>(message, requestCallback, state);
		}

		/// <summary>
		///   Send an dynamic update to the dns server and returns the answer asynchronously.
		/// </summary>
		/// <param name="message"> Update, that should be send to the dns server </param>
		/// <param name="requestCallback">
		///   An <see cref="System.AsyncCallback" /> delegate that references the method to invoked then the operation is complete.
		/// </param>
		/// <param name="state">
		///   A user-defined object that contains information about the receive operation. This object is passed to the
		///   <paramref
		///     name="requestCallback" />
		///   delegate when the operation is complete.
		/// </param>
		/// <returns>
		///   An <see cref="System.IAsyncResult" /> IAsyncResult object that references the asynchronous receive.
		/// </returns>
		public IAsyncResult BeginSendUpdate(DnsUpdateMessage message, AsyncCallback requestCallback, object state)
		{
			if (message == null)
				throw new ArgumentNullException("message");

			if (String.IsNullOrEmpty(message.ZoneName))
				throw new ArgumentException("Zone name must be provided", "message");

			return BeginSendMessage(message, requestCallback, state);
		}

		/// <summary>
		///   Ends a pending asynchronous operation.
		/// </summary>
		/// <param name="ar">
		///   An <see cref="System.IAsyncResult" /> object returned by a call to
		///   <see
		///     cref="ARSoft.Tools.Net.Dns.DnsClient.BeginSendMessage" />
		///   .
		/// </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsMessage EndSendMessage(IAsyncResult ar)
		{
			return EndSendMessage<DnsMessage>(ar).FirstOrDefault();
		}

		/// <summary>
		///   Ends a pending asynchronous operation.
		/// </summary>
		/// <param name="ar">
		///   An <see cref="System.IAsyncResult" /> object returned by a call to
		///   <see
		///     cref="ARSoft.Tools.Net.Dns.DnsClient.BeginSendUpdate" />
		///   .
		/// </param>
		/// <returns> The complete response of the dns server </returns>
		public DnsUpdateMessage EndSendUpdate(IAsyncResult ar)
		{
			return EndSendMessage<DnsUpdateMessage>(ar).FirstOrDefault();
		}

		#region Event handling async udp query
		#endregion

		#region Event handling async tcp query
		#endregion

		private static List<IPAddress> GetDnsServers()
		{
			List<IPAddress> res = new List<IPAddress>();

			try
			{
				foreach (NetworkInterface nic in NetworkInterface.GetAllNetworkInterfaces())
				{
					if ((nic.OperationalStatus == OperationalStatus.Up) && (nic.NetworkInterfaceType != NetworkInterfaceType.Loopback))
					{
						foreach (IPAddress dns in nic.GetIPProperties().DnsAddresses)
						{
							// only use servers defined in draft-ietf-ipngwg-dns-discovery if they are in the same subnet
							// fec0::/10 is marked deprecated in RFC 3879, so nobody should use these addresses
							if (dns.AddressFamily == AddressFamily.InterNetworkV6)
							{
								IPAddress unscoped = new IPAddress(dns.GetAddressBytes());
								if (unscoped.Equals(IPAddress.Parse("fec0:0:0:ffff::1"))
										|| unscoped.Equals(IPAddress.Parse("fec0:0:0:ffff::2"))
										|| unscoped.Equals(IPAddress.Parse("fec0:0:0:ffff::3")))
								{
									if (!nic.GetIPProperties().UnicastAddresses.Any(x => x.Address.GetNetworkAddress(10).Equals(IPAddress.Parse("fec0::"))))
										continue;
								}
							}

							if (!res.Contains(dns))
								res.Add(dns);
						}
					}
				}
			}
			catch (Exception e)
			{
				Trace.TraceError("Configured nameserver couldn't be determined: " + e);
			}

			// try parsing resolv.conf since getting data by NetworkInterface is not supported on non-windows mono
			if ((res.Count == 0) && ((Environment.OSVersion.Platform == PlatformID.Unix) || (Environment.OSVersion.Platform == PlatformID.MacOSX)))
			{
				try
				{
					using (StreamReader reader = File.OpenText("/etc/resolv.conf"))
					{
						string line;
						while ((line = reader.ReadLine()) != null)
						{
							int commentStart = line.IndexOf('#');
							if (commentStart != -1)
							{
								line = line.Substring(0, commentStart);
							}

							string[] lineData = line.Split(new[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
							IPAddress dns;
							if ((lineData.Length == 2) && (lineData[0] == "nameserver") && (IPAddress.TryParse(lineData[1], out dns)))
							{
								res.Add(dns);
							}
						}
					}
				}
				catch (Exception e)
				{
					Trace.TraceError("/etc/resolv.conf could not be parsed: " + e);
				}
			}

			if (res.Count == 0)
			{
				// fallback: use the public dns-resolvers of google
				res.Add(IPAddress.Parse("8.8.4.4"));
				res.Add(IPAddress.Parse("8.8.8.8"));
			}

			return res.OrderBy(x => x.AddressFamily == AddressFamily.InterNetworkV6 ? 1 : 0).ToList();
		}
	}
}