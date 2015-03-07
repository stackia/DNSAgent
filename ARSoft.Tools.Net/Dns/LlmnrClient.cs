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

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Provides a client for querying LLMNR (link-local multicast name resolution) as defined in
	///   <see
	///     cref="!:http://tools.ietf.org/html/rfc4795">
	///     RFC 4795
	///   </see>
	///   .
	/// </summary>
	public class LlmnrClient : DnsClientBase
	{
		private static readonly List<IPAddress> _addresses = new List<IPAddress> { IPAddress.Parse("FF02::1:3"), IPAddress.Parse("224.0.0.252") };

		/// <summary>
		///   Provides a new instance with a timeout of 1 second
		/// </summary>
		public LlmnrClient()
			: this(1000) {}

		/// <summary>
		///   Provides a new instance with a custom timeout
		/// </summary>
		/// <param name="queryTimeout"> Query timeout in milliseconds </param>
		public LlmnrClient(int queryTimeout)
			: base(_addresses, queryTimeout, 5355)
		{
			int maximumMessageSize = 0;

			try
			{
				maximumMessageSize = NetworkInterface.GetAllNetworkInterfaces()
				                                     .Where(n => n.SupportsMulticast && (n.NetworkInterfaceType != NetworkInterfaceType.Loopback) && (n.OperationalStatus == OperationalStatus.Up) && (n.Supports(NetworkInterfaceComponent.IPv4)))
				                                     .Select(n => n.GetIPProperties())
				                                     .Min(p => Math.Min(p.GetIPv4Properties().Mtu, p.GetIPv6Properties().Mtu));
			}
			catch {}

			_maximumMessageSize = Math.Max(512, maximumMessageSize);
		}

		private readonly int _maximumMessageSize;

		protected override int MaximumQueryMessageSize
		{
			get { return _maximumMessageSize; }
		}

		protected override bool AreMultipleResponsesAllowedInParallelMode
		{
			get { return true; }
		}

		/// <summary>
		///   Queries for specified records.
		/// </summary>
		/// <param name="name"> Domain, that should be queried </param>
		/// <returns> All available responses on the local network </returns>
		public List<LlmnrMessage> Resolve(string name)
		{
			return Resolve(name, RecordType.A);
		}

		/// <summary>
		///   Queries for specified records.
		/// </summary>
		/// <param name="name"> Name, that should be queried </param>
		/// <param name="recordType"> Type the should be queried </param>
		/// <returns> All available responses on the local network </returns>
		public List<LlmnrMessage> Resolve(string name, RecordType recordType)
		{
			if (String.IsNullOrEmpty(name))
			{
				throw new ArgumentException("Name must be provided", "name");
			}

			LlmnrMessage message = new LlmnrMessage { IsQuery = true, OperationCode = OperationCode.Query };
			message.Questions.Add(new DnsQuestion(name, recordType, RecordClass.INet));

			return SendMessageParallel(message);
		}

		/// <summary>
		///   Queries for specified records asynchronously.
		/// </summary>
		/// <param name="name"> Name, that should be queried </param>
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
			return BeginResolve(name, RecordType.A, requestCallback, state);
		}

		/// <summary>
		///   Queries for specified records asynchronously.
		/// </summary>
		/// <param name="name"> Name, that should be queried </param>
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
			if (String.IsNullOrEmpty(name))
			{
				throw new ArgumentException("Name must be provided", "name");
			}

			LlmnrMessage message = new LlmnrMessage { IsQuery = true, OperationCode = OperationCode.Query };
			message.Questions.Add(new DnsQuestion(name, recordType, RecordClass.INet));

			return BeginSendMessageParallel(message, requestCallback, state);
		}

		/// <summary>
		///   Ends a pending asynchronous operation.
		/// </summary>
		/// <param name="ar">
		///   An <see cref="System.IAsyncResult" /> object returned by a call to
		///   <see
		///     cref="ARSoft.Tools.Net.Dns.LlmnrClient.BeginResolve" />
		///   .
		/// </param>
		/// <returns> All available responses on the local network </returns>
		public List<LlmnrMessage> EndResolve(IAsyncResult ar)
		{
			return EndSendMessageParallel<LlmnrMessage>(ar);
		}
	}
}