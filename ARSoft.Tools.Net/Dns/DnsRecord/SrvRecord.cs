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
	///   <para>Server selector</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc2782">RFC 2782</see>
	///   </para>
	/// </summary>
	public class SrvRecord : DnsRecordBase
	{
		/// <summary>
		///   Priority of the record
		/// </summary>
		public ushort Priority { get; private set; }

		/// <summary>
		///   Relative weight for records with the same priority
		/// </summary>
		public ushort Weight { get; private set; }

		/// <summary>
		///   The port of the service on the target
		/// </summary>
		public ushort Port { get; private set; }

		/// <summary>
		///   Domain name of the target host
		/// </summary>
		public string Target { get; private set; }

		internal SrvRecord() {}

		/// <summary>
		///   Creates a new instance of the SrvRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="priority"> Priority of the record </param>
		/// <param name="weight"> Relative weight for records with the same priority </param>
		/// <param name="port"> The port of the service on the target </param>
		/// <param name="target"> Domain name of the target host </param>
		public SrvRecord(string name, int timeToLive, ushort priority, ushort weight, ushort port, string target)
			: base(name, RecordType.Srv, RecordClass.INet, timeToLive)
		{
			Priority = priority;
			Weight = weight;
			Port = port;
			Target = target ?? String.Empty;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Priority = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Weight = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Port = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Target = DnsMessageBase.ParseDomainName(resultData, ref startPosition);
		}

		internal override string RecordDataToString()
		{
			return Priority
			       + " " + Weight
			       + " " + Port
			       + " " + Target;
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return Target.Length + 8; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Priority);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Weight);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Port);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, Target, false, domainNames);
		}
	}
}