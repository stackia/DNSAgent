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
	///   <para>Security Key</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
	///     ,
	///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
	///     ,
	///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
	///     and
	///     <see cref="!:http://tools.ietf.org/html/rfc2930">RFC 2930</see>
	///   </para>
	/// </summary>
	public abstract class KeyRecordBase : DnsRecordBase
	{
		/// <summary>
		///   Type of key
		/// </summary>
		public enum KeyTypeFlag : ushort
		{
			/// <summary>
			///   <para>Use of the key is prohibited for authentication</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			AuthenticationProhibited = 0x8000,

			/// <summary>
			///   <para>Use of the key is prohibited for confidentiality</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			ConfidentialityProhibited = 0x4000,

			/// <summary>
			///   <para>Use of the key for authentication and/or confidentiality is permitted</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			BothProhibited = 0x0000,

			/// <summary>
			///   <para>There is no key information</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			NoKey = 0xc000,
		}

		/// <summary>
		///   Type of name
		/// </summary>
		public enum NameTypeFlag : ushort
		{
			/// <summary>
			///   <para>Key is associated with a user or account</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			User = 0x0000,

			/// <summary>
			///   <para>Key is associated with a zone</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			Zone = 0x0100,

			/// <summary>
			///   <para>Key is associated with a host</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			Host = 0x0200,

			/// <summary>
			///   <para>Reserved</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			Reserved = 0x0300,
		}

		/// <summary>
		///   Protocol for which the key is used
		/// </summary>
		public enum ProtocolType : byte
		{
			/// <summary>
			///   <para>Use in connection with TLS</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			Tls = 1,

			/// <summary>
			///   <para>Use in connection with email</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			Email = 2,

			/// <summary>
			///   <para>Used for DNS security</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			DnsSec = 3,

			/// <summary>
			///   <para>Refer to the Oakley/IPSEC  protocol</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			IpSec = 4,

			/// <summary>
			///   <para>Used in connection with any protocol</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
			///   </para>
			/// </summary>
			Any = 255,
		}

		/// <summary>
		///   Flags of the key
		/// </summary>
		public ushort Flags { get; private set; }

		/// <summary>
		///   Protocol for which the key is used
		/// </summary>
		public ProtocolType Protocol { get; private set; }

		/// <summary>
		///   Algorithm of the key
		/// </summary>
		public DnsSecAlgorithm Algorithm { get; private set; }

		#region Flags
		/// <summary>
		///   Type of key
		/// </summary>
		public KeyTypeFlag Type
		{
			get { return (KeyTypeFlag) (Flags & 0xc000); }
			set
			{
				ushort clearedOp = (ushort) (Flags & 0x3fff);
				Flags = (ushort) (clearedOp | (ushort) value);
			}
		}

		/// <summary>
		///   True, if a second flag field should be added
		/// </summary>
		public bool IsExtendedFlag
		{
			get { return (Flags & 0x1000) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x1000;
				}
				else
				{
					Flags &= 0xefff;
				}
			}
		}

		/// <summary>
		///   Type of name
		/// </summary>
		public NameTypeFlag NameType
		{
			get { return (NameTypeFlag) (Flags & 0x0300); }
			set
			{
				ushort clearedOp = (ushort) (Flags & 0xfcff);
				Flags = (ushort) (clearedOp | (ushort) value);
			}
		}

		/// <summary>
		///   Is the key authorized for zone updates
		/// </summary>
		public bool IsZoneSignatory
		{
			get { return (Flags & 0x0008) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x0008;
				}
				else
				{
					Flags &= 0xfff7;
				}
			}
		}

		/// <summary>
		///   Is the key authorized for updates of records signed with other key
		/// </summary>
		public bool IsStrongSignatory
		{
			get { return (Flags & 0x0004) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x0004;
				}
				else
				{
					Flags &= 0xfffb;
				}
			}
		}

		/// <summary>
		///   Is the key only authorized for update of records with the same record name as the key
		/// </summary>
		public bool IsUniqueSignatory
		{
			get { return (Flags & 0x0002) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x0002;
				}
				else
				{
					Flags &= 0xfffd;
				}
			}
		}

		/// <summary>
		///   Is the key an update key
		/// </summary>
		public bool IsGeneralSignatory
		{
			get { return (Flags & 0x0001) != 0; }
			set
			{
				if (value)
				{
					Flags |= 0x0001;
				}
				else
				{
					Flags &= 0xfffe;
				}
			}
		}
		#endregion

		protected KeyRecordBase() {}

		protected KeyRecordBase(string name, RecordClass recordClass, int timeToLive, ushort flags, ProtocolType protocol, DnsSecAlgorithm algorithm)
			: base(name, RecordType.Key, recordClass, timeToLive)
		{
			Flags = flags;
			Protocol = protocol;
			Algorithm = algorithm;
		}

		internal override sealed void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			Flags = DnsMessageBase.ParseUShort(resultData, ref startPosition);
			Protocol = (ProtocolType) resultData[startPosition++];
			Algorithm = (DnsSecAlgorithm) resultData[startPosition++];
			ParsePublicKey(resultData, startPosition, length - 4);
		}

		protected abstract void ParsePublicKey(byte[] resultData, int startPosition, int length);

		internal override sealed string RecordDataToString()
		{
			return Flags
			       + " " + (byte) Protocol
			       + " " + (byte) Algorithm
			       + " " + PublicKeyToString();
		}

		protected abstract string PublicKeyToString();

		protected internal override sealed int MaximumRecordDataLength
		{
			get { return 4 + MaximumPublicKeyLength; }
		}

		protected abstract int MaximumPublicKeyLength { get; }

		protected internal override sealed void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeUShort(messageData, ref currentPosition, Flags);
			messageData[currentPosition++] = (byte) Protocol;
			messageData[currentPosition++] = (byte) Algorithm;
			EncodePublicKey(messageData, offset, ref currentPosition, domainNames);
		}

		protected abstract void EncodePublicKey(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames);
	}
}