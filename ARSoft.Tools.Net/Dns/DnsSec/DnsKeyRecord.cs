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
	///   <para>DNS Key record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
	///     and
	///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
	///   </para>
	/// </summary>
	public class DnsKeyRecord : DnsRecordBase
	{
		/// <summary>
		///   Flags of the key
		/// </summary>
		public ushort Flags { get; private set; }

		/// <summary>
		///   Protocol field
		/// </summary>
		public byte Protocol { get; private set; }

		/// <summary>
		///   Algorithm of the key
		/// </summary>
		public DnsSecAlgorithm Algorithm { get; private set; }

		/// <summary>
		///   Binary data of the public key
		/// </summary>
		public byte[] PublicKey { get; private set; }

		/// <summary>
		///   Record holds a DNS zone key
		/// </summary>
		public bool IsZoneKey
		{
			get { return (Flags & 0x100) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x100;
				}
				else
				{
					Flags &= 0xfeff;
				}
			}
		}

		/// <summary>
		///   <para>Key is intended for use as a secure entry point</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc3757">RFC 3757</see>
		///   </para>
		/// </summary>
		public bool IsSecureEntryPoint
		{
			get { return (Flags & 0x01) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x01;
				}
				else
				{
					Flags &= 0xfffe;
				}
			}
		}

		internal DnsKeyRecord() {}

		/// <summary>
		///   Creates a new instance of the DnsKeyRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="recordClass"> Class of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="flags"> Flags of the key </param>
		/// <param name="protocol"> Protocol field </param>
		/// <param name="algorithm"> Algorithm of the key </param>
		/// <param name="publicKey"> Binary data of the public key </param>
		public DnsKeyRecord(string name, RecordClass recordClass, int timeToLive, ushort flags, byte protocol, DnsSecAlgorithm algorithm, byte[] publicKey)
			: base(name, RecordType.DnsKey, recordClass, timeToLive)
		{
			Flags = flags;
			Protocol = protocol;
			Algorithm = algorithm;
			PublicKey = publicKey ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Flags = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Protocol = resultData[startPosition++];
			Algorithm = (DnsSecAlgorithm) resultData[startPosition++];
			PublicKey = DnsMessageBase.ParseByteData(resultData, ref startPosition, length - 4);
		}

		internal override string RecordDataToString()
		{
			return Flags
			       + " " + Protocol
			       + " " + (byte) Algorithm
			       + " " + PublicKey.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 4 + PublicKey.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Flags);
			messageData[currentPosition++] = Protocol;
			messageData[currentPosition++] = (byte) Algorithm;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, PublicKey);
		}
	}
}