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
	///   <para>NID</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc6742">RFC 6742</see>
	///   </para>
	/// </summary>
	public class NIdRecord : DnsRecordBase
	{
		/// <summary>
		///   The preference
		/// </summary>
		public ushort Preference { get; private set; }

		/// <summary>
		///   The Node ID
		/// </summary>
		public ulong NodeID { get; private set; }

		internal NIdRecord() {}

		/// <summary>
		///   Creates a new instance of the NIdRecord class
		/// </summary>
		/// <param name="name"> Domain name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="preference"> The preference </param>
		/// <param name="nodeID"> The Node ID </param>
		public NIdRecord(string name, int timeToLive, ushort preference, ulong nodeID)
			: base(name, RecordType.NId, RecordClass.INet, timeToLive)
		{
			Preference = preference;
			NodeID = nodeID;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Preference = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			NodeID = DnsMessageBase.ParseULong(resultData, ref startPosition);
		}

		internal override string RecordDataToString()
		{
			string nodeID = NodeID.ToString("x16");
			return Preference + " " + nodeID.Substring(0, 4) + ":" + nodeID.Substring(4, 4) + ":" + nodeID.Substring(8, 4) + ":" + nodeID.Substring(12);
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 10; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Preference);
			DnsMessageBase.EncodeULong(messageData, ref currentPosition, NodeID);
		}
	}
}