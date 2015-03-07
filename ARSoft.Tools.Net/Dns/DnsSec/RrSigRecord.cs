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
	///   <para>Record signature record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
	///     and
	///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
	///   </para>
	/// </summary>
	public class RrSigRecord : DnsRecordBase
	{
		/// <summary>
		///   <see cref="RecordType">Record type</see> that is covered by this record
		/// </summary>
		public RecordType TypeCovered { get; private set; }

		/// <summary>
		///   <see cref="DnsSecAlgorithm">Algorithm</see> that is used for signature
		/// </summary>
		public DnsSecAlgorithm Algorithm { get; private set; }

		/// <summary>
		///   Label count of original record that is covered by this record
		/// </summary>
		public byte Labels { get; private set; }

		/// <summary>
		///   Original time to live value of original record that is covered by this record
		/// </summary>
		public int OriginalTimeToLive { get; private set; }

		/// <summary>
		///   Signature is valid until this date
		/// </summary>
		public DateTime SignatureExpiration { get; private set; }

		/// <summary>
		///   Signature is valid from this date
		/// </summary>
		public DateTime SignatureInception { get; private set; }

		/// <summary>
		///   Key tag
		/// </summary>
		public ushort KeyTag { get; private set; }

		/// <summary>
		///   Domain name of generator of the signature
		/// </summary>
		public string SignersName { get; private set; }

		/// <summary>
		///   Binary data of the signature
		/// </summary>
		public byte[] Signature { get; private set; }

		internal RrSigRecord() {}

		/// <summary>
		///   Creates a new instance of the RrSigRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="recordClass"> Class of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="typeCovered">
		///   <see cref="RecordType">Record type</see> that is covered by this record
		/// </param>
		/// <param name="algorithm">
		///   <see cref="DnsSecAlgorithm">Algorithm</see> that is used for signature
		/// </param>
		/// <param name="labels"> Label count of original record that is covered by this record </param>
		/// <param name="originalTimeToLive"> Original time to live value of original record that is covered by this record </param>
		/// <param name="signatureExpiration"> Signature is valid until this date </param>
		/// <param name="signatureInception"> Signature is valid from this date </param>
		/// <param name="keyTag"> Key tag </param>
		/// <param name="signersName"> Domain name of generator of the signature </param>
		/// <param name="signature"> Binary data of the signature </param>
		public RrSigRecord(string name, RecordClass recordClass, int timeToLive, RecordType typeCovered, DnsSecAlgorithm algorithm, byte labels, int originalTimeToLive, DateTime signatureExpiration, DateTime signatureInception, ushort keyTag, string signersName, byte[] signature)
			: base(name, RecordType.RrSig, recordClass, timeToLive)
		{
			TypeCovered = typeCovered;
			Algorithm = algorithm;
			Labels = labels;
			OriginalTimeToLive = originalTimeToLive;
			SignatureExpiration = signatureExpiration;
			SignatureInception = signatureInception;
			KeyTag = keyTag;
			SignersName = signersName ?? String.Empty;
			Signature = signature ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			int currentPosition = startPosition;

			TypeCovered = (RecordType) DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			Algorithm = (DnsSecAlgorithm) resultData[currentPosition++];
			Labels = resultData[currentPosition++];
			OriginalTimeToLive = DnsMessageBase.ParseInt(resultData, ref currentPosition);
			SignatureExpiration = ParseDateTime(resultData, ref currentPosition);
			SignatureInception = ParseDateTime(resultData, ref currentPosition);
			KeyTag = DnsMessageBase.ParseUShort(resultData, ref currentPosition);
			SignersName = DnsMessageBase.ParseDomainName(resultData, ref currentPosition);
			Signature = DnsMessageBase.ParseByteData(resultData, ref currentPosition, length + startPosition - currentPosition);
		}

		internal override string RecordDataToString()
		{
			return ToString(TypeCovered)
			       + " " + (byte) Algorithm
			       + " " + Labels
			       + " " + OriginalTimeToLive
			       + " " + SignatureExpiration.ToString("yyyyMMddHHmmss")
			       + " " + SignatureInception.ToString("yyyyMMddHHmmss")
			       + " " + KeyTag
			       + " " + SignersName
			       + " " + Signature.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 20 + SignersName.Length + Signature.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) TypeCovered);
			messageData[currentPosition++] = (byte) Algorithm;
			messageData[currentPosition++] = Labels;
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, OriginalTimeToLive);
			EncodeDateTime(messageData, ref currentPosition, SignatureExpiration);
			EncodeDateTime(messageData, ref currentPosition, SignatureInception);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, KeyTag);
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, SignersName, false, null);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, Signature);
		}

		internal static void EncodeDateTime(byte[] buffer, ref int currentPosition, DateTime value)
		{
			int timeStamp = (int) (value.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;
			DnsMessageBase.EncodeInt(buffer, ref currentPosition, timeStamp);
		}

		private static DateTime ParseDateTime(byte[] buffer, ref int currentPosition)
		{
			int timeStamp = DnsMessageBase.ParseInt(buffer, ref currentPosition);
			return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(timeStamp).ToLocalTime();
		}
	}
}