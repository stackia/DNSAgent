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
	///   <para>Transaction signature record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc2845">RFC 2845</see>
	///   </para>
	/// </summary>
	public class TSigRecord : DnsRecordBase
	{
		/// <summary>
		///   Algorithm of the key
		/// </summary>
		public TSigAlgorithm Algorithm { get; private set; }

		/// <summary>
		///   Time when the data was signed
		/// </summary>
		public DateTime TimeSigned { get; internal set; }

		/// <summary>
		///   Timespan errors permitted
		/// </summary>
		public TimeSpan Fudge { get; private set; }

		/// <summary>
		///   MAC defined by algorithm
		/// </summary>
		public byte[] Mac { get; internal set; }

		/// <summary>
		///   Original ID of message
		/// </summary>
		public ushort OriginalID { get; private set; }

		/// <summary>
		///   Error field
		/// </summary>
		public ReturnCode Error { get; internal set; }

		/// <summary>
		///   Binary other data
		/// </summary>
		public byte[] OtherData { get; internal set; }

		/// <summary>
		///   Binary data of the key
		/// </summary>
		public byte[] KeyData { get; internal set; }

		/// <summary>
		///   Result of validation of record
		/// </summary>
		public ReturnCode ValidationResult { get; internal set; }

		internal TSigRecord() {}

		/// <summary>
		///   Creates a new instance of the TSigRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="algorithm"> Algorithm of the key </param>
		/// <param name="timeSigned"> Time when the data was signed </param>
		/// <param name="fudge"> Timespan errors permitted </param>
		/// <param name="originalID"> Original ID of message </param>
		/// <param name="error"> Error field </param>
		/// <param name="otherData"> Binary other data </param>
		/// <param name="keyData"> Binary data of the key </param>
		public TSigRecord(string name, TSigAlgorithm algorithm, DateTime timeSigned, TimeSpan fudge, ushort originalID, ReturnCode error, byte[] otherData, byte[] keyData)
			: base(name, RecordType.TSig, RecordClass.Any, 0)
		{
			Algorithm = algorithm;
			TimeSigned = timeSigned;
			Fudge = fudge;
			Mac = new byte[] { };
			OriginalID = originalID;
			Error = error;
			OtherData = otherData ?? new byte[] { };
			KeyData = keyData;
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Algorithm = TSigAlgorithmHelper.GetAlgorithmByName(DnsMessageBase.ParseDomainName(resultData, ref startPosition));
			TimeSigned = ParseDateTime(resultData, ref startPosition);
			Fudge = TimeSpan.FromSeconds(DnsMessageBase.ParseUShort(resultData, ref startPosition));
			int macSize = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Mac = DnsMessageBase.ParseByteData(resultData, ref startPosition, macSize);
			OriginalID = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Error = (ReturnCode) DnsMessageBase.ParseUShort(resultData, ref startPosition);
			int otherDataSize = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			OtherData = DnsMessageBase.ParseByteData(resultData, ref startPosition, otherDataSize);
		}

		internal override string RecordDataToString()
		{
			return TSigAlgorithmHelper.GetDomainName(Algorithm)
			       + " " + (int) (TimeSigned - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds
			       + " " + (ushort) Fudge.TotalSeconds
			       + " " + Mac.Length
			       + " " + Mac.ToBase64String()
			       + " " + OriginalID
			       + " " + (ushort) Error
			       + " " + OtherData.Length
			       + " " + OtherData.ToBase64String();
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return TSigAlgorithmHelper.GetDomainName(Algorithm).Length + 18 + TSigAlgorithmHelper.GetHashSize(Algorithm) + OtherData.Length; }
		}

		internal void Encode(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames, byte[] mac)
		{
			int recordDataOffset;
			EncodeRecordHeader(messageData, offset, ref currentPosition, domainNames, out recordDataOffset);

			EncodeRecordData(messageData, offset, ref recordDataOffset, domainNames, mac);

			EncodeRecordLength(messageData, offset, ref currentPosition, domainNames, recordDataOffset);
		}

		private void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames, byte[] mac)
		{
			DnsMessageBase.EncodeDomainName(messageData, offset, ref currentPosition, TSigAlgorithmHelper.GetDomainName(Algorithm), false, domainNames);
			EncodeDateTime(messageData, ref currentPosition, TimeSigned);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Fudge.TotalSeconds);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) mac.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, mac);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, OriginalID);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) Error);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) OtherData.Length);
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, OtherData);
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			EncodeRecordData(messageData, offset, ref currentPosition, domainNames, Mac);
		}

		internal static void EncodeDateTime(byte[] buffer, ref int currentPosition, DateTime value)
		{
			long timeStamp = (long) (value.ToUniversalTime() - new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)).TotalSeconds;

			if (BitConverter.IsLittleEndian)
			{
				buffer[currentPosition++] = (byte) ((timeStamp >> 40) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 32) & 0xff);
				buffer[currentPosition++] = (byte) (timeStamp >> 24 & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 16) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 8) & 0xff);
				buffer[currentPosition++] = (byte) (timeStamp & 0xff);
			}
			else
			{
				buffer[currentPosition++] = (byte) (timeStamp & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 8) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 16) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 24) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 32) & 0xff);
				buffer[currentPosition++] = (byte) ((timeStamp >> 40) & 0xff);
			}
		}

		private static DateTime ParseDateTime(byte[] buffer, ref int currentPosition)
		{
			long timeStamp;

			if (BitConverter.IsLittleEndian)
			{
				timeStamp = ((buffer[currentPosition++] << 40) | (buffer[currentPosition++] << 32) | buffer[currentPosition++] << 24 | (buffer[currentPosition++] << 16) | (buffer[currentPosition++] << 8) | buffer[currentPosition++]);
			}
			else
			{
				timeStamp = (buffer[currentPosition++] | (buffer[currentPosition++] << 8) | (buffer[currentPosition++] << 16) | (buffer[currentPosition++] << 24) | (buffer[currentPosition++] << 32) | (buffer[currentPosition++] << 40));
			}

			return new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(timeStamp).ToLocalTime();
		}
	}
}