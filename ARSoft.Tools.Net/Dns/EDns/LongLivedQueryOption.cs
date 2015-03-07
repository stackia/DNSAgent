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
	///   <para>Long lived query option</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://files.dns-sd.org/draft-sekar-dns-llq.txt">draft-sekar-dns-llq</see>
	///   </para>
	/// </summary>
	public class LongLivedQueryOption : EDnsOptionBase
	{
		/// <summary>
		///   Long lived query operation codes
		/// </summary>
		public enum LlqOperationCode : ushort
		{
			/// <summary>
			///   Setup a LLQ
			/// </summary>
			Setup = 1,

			/// <summary>
			///   Refresh a LLQ
			/// </summary>
			Refresh = 2,

			/// <summary>
			///   LLQ event
			/// </summary>
			Event = 3,
		}

		/// <summary>
		///   Long lived query error codes
		/// </summary>
		public enum LlqErrorCode : ushort
		{
			/// <summary>
			///   The LLQ Setup Request was successful.
			/// </summary>
			NoError = 0,

			/// <summary>
			///   The server cannot grant the LLQ request because it is overloaded, or the request exceeds the server's rate limit.
			/// </summary>
			ServerFull = 1,

			/// <summary>
			///   The data for this name and type is not expected to change frequently, and the server therefore does not support the requested LLQ.
			/// </summary>
			Static = 2,

			/// <summary>
			///   The LLQ was improperly formatted
			/// </summary>
			FormatError = 3,

			/// <summary>
			///   The requested LLQ is expired or non-existent
			/// </summary>
			NoSuchLlq = 4,

			/// <summary>
			///   The protocol version specified in the client's request is not supported by the server.
			/// </summary>
			BadVersion = 5,

			/// <summary>
			///   The LLQ was not granted for an unknown reason.
			/// </summary>
			UnknownError = 6,
		}

		/// <summary>
		///   Version of LLQ protocol implemented
		/// </summary>
		public ushort Version { get; private set; }

		/// <summary>
		///   Identifies LLQ operation
		/// </summary>
		public LlqOperationCode OperationCode { get; private set; }

		/// <summary>
		///   Identifies LLQ errors
		/// </summary>
		public LlqErrorCode ErrorCode { get; private set; }

		/// <summary>
		///   Identifier for an LLQ
		/// </summary>
		public ulong Id { get; private set; }

		/// <summary>
		///   Requested or granted life of LLQ
		/// </summary>
		public TimeSpan LeaseTime { get; private set; }

		internal LongLivedQueryOption()
			: base(EDnsOptionType.LongLivedQuery) {}

		/// <summary>
		///   Creates a new instance of the LongLivedQueryOption class
		/// </summary>
		/// <param name="operationCode"> Identifies LLQ operation </param>
		/// <param name="errorCode"> Identifies LLQ errors </param>
		/// <param name="id"> Identifier for an LLQ </param>
		/// <param name="leaseTime"> Requested or granted life of LLQ </param>
		public LongLivedQueryOption(LlqOperationCode operationCode, LlqErrorCode errorCode, ulong id, TimeSpan leaseTime)
			: this(0, operationCode, errorCode, id, leaseTime) {}

		/// <summary>
		///   Creates a new instance of the LongLivedQueryOption class
		/// </summary>
		/// <param name="version"> Version of LLQ protocol implemented </param>
		/// <param name="operationCode"> Identifies LLQ operation </param>
		/// <param name="errorCode"> Identifies LLQ errors </param>
		/// <param name="id"> Identifier for an LLQ </param>
		/// <param name="leaseTime"> Requested or granted life of LLQ </param>
		public LongLivedQueryOption(ushort version, LlqOperationCode operationCode, LlqErrorCode errorCode, ulong id, TimeSpan leaseTime)
			: this()
		{
			Version = version;
			OperationCode = operationCode;
			ErrorCode = errorCode;
			Id = id;
			LeaseTime = leaseTime;
		}

		internal override void ParseData(byte[] resultData, int startPosition, int length)
		{
			Version = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			OperationCode = (LlqOperationCode) DnsMessageBase.ParseUShort(resultData, ref startPosition);
			ErrorCode = (LlqErrorCode) DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Id = DnsMessageBase.ParseULong(resultData, ref startPosition);
			LeaseTime = TimeSpan.FromSeconds(DnsMessageBase.ParseUInt(resultData, ref startPosition));
		}

		internal override ushort DataLength
		{
			get { return 18; }
		}

		internal override void EncodeData(byte[] messageData, ref int currentPosition)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Version);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) OperationCode);
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, (ushort) ErrorCode);
			DnsMessageBase.EncodeULong(messageData, ref currentPosition, Id);
			DnsMessageBase.EncodeUInt(messageData, ref currentPosition, (uint) LeaseTime.TotalSeconds);
		}
	}
}