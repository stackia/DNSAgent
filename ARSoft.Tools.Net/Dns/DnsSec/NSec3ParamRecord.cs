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
	///   <para>Hashed next owner parameter record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc5155">RFC 5155</see>
	///   </para>
	/// </summary>
	public class NSec3ParamRecord : DnsRecordBase
	{
		/// <summary>
		///   Algorithm of the hash
		/// </summary>
		public DnsSecAlgorithm HashAlgorithm { get; private set; }

		/// <summary>
		///   Flags of the record
		/// </summary>
		public byte Flags { get; private set; }

		/// <summary>
		///   Number of iterations
		/// </summary>
		public ushort Iterations { get; private set; }

		/// <summary>
		///   Binary data of salt
		/// </summary>
		public byte[] Salt { get; private set; }

		internal NSec3ParamRecord() {}

		/// <summary>
		///   Creates a new instance of the NSec3ParamRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="recordClass"> Class of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="hashAlgorithm"> Algorithm of hash </param>
		/// <param name="flags"> Flags of the record </param>
		/// <param name="iterations"> Number of iterations </param>
		/// <param name="salt"> Binary data of salt </param>
		public NSec3ParamRecord(string name, RecordClass recordClass, int timeToLive, DnsSecAlgorithm hashAlgorithm, byte flags, ushort iterations, byte[] salt)
			: base(name, RecordType.NSec3Param, recordClass, timeToLive)
		{
			HashAlgorithm = hashAlgorithm;
			Flags = flags;
			Iterations = iterations;
			Salt = salt ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			HashAlgorithm = (DnsSecAlgorithm) resultData[currentPosition++];
			Flags = resultData[currentPosition++];
			Iterations = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			int saltLength = resultData[currentPosition++];
			Salt = DnsMessageBase.ParseByteData(resultData, ref currentPosition, saltLength);
		}

		internal override string RecordDataToString()
		{
			return (byte) HashAlgorithm
			       + " " + Flags
			       + " " + Iterations
			       + " " + ((Salt.Length == 0) ? "-" : Salt.ToBase16String());
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 5 + Salt.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			messageData[currentPosition++] = (byte) HashAlgorithm;
			messageData[currentPosition++] = Flags;
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Iterations);
			messageData[currentPosition++] = (byte) Salt.Length;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Salt);
		}
	}
}