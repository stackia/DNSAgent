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
	///     <see cref="!:http://tools.ietf.org/html/rfc6698">RFC 6698</see>
	///   </para>
	/// </summary>
	public class TlsaRecord : DnsRecordBase
	{
		/// <summary>
		///   Certificate Usage
		/// </summary>
		public enum TlsaCertificateUsage : byte
		{
			/// <summary>
			///   <para>CA certificate, or the public key of such a certificate</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc6698">RFC 6698</see>
			///   </para>
			/// </summary>
			CACertificate = 0,

			/// <summary>
			///   <para>End entity certificate, or the public key of such a certificate</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc6698">RFC 6698</see>
			///   </para>
			/// </summary>
			EndEntityCertificate = 1,

			/// <summary>
			///   <para> Certificate, or the public key of such a certificate, that MUST be used as the trust anchor</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc6698">RFC 6698</see>
			///   </para>
			/// </summary>
			TrustAnchorCertificate = 2,

			/// <summary>
			///   <para>certificate, or the public key of such a certificate, that MUST match the end entity certificate given by the server in TLS</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc6698">RFC 6698</see>
			///   </para>
			/// </summary>
			DomainIssuedCertificate = 3,
		}

		/// <summary>
		///   Selector
		/// </summary>
		public enum TlsaSelector : byte
		{
			/// <summary>
			///   <para>Full certificate</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc6698">RFC 6698</see>
			///   </para>
			/// </summary>
			FullCertificate = 0,

			/// <summary>
			///   <para>DER-encoded binary structure</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc6698">RFC 6698</see>
			///   </para>
			/// </summary>
			SubjectPublicKeyInfo = 1,
		}

		/// <summary>
		///   Matching Type
		/// </summary>
		public enum TlsaMatchingType : byte
		{
			/// <summary>
			///   <para>ExactMatch</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc6698">RFC 6698</see>
			///   </para>
			/// </summary>
			ExactMatch = 0,

			/// <summary>
			///   <para>SHA-256 hash</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc6698">RFC 6698</see>
			///   </para>
			/// </summary>
			Sha256Hash = 1,

			/// <summary>
			///   <para>SHA-512 hash</para>
			///   <para>
			///     Defined in
			///     <see cref="!:http://tools.ietf.org/html/rfc6698">RFC 6698</see>
			///   </para>
			/// </summary>
			Sha512Hash = 2,
		}

		/// <summary>
		///   The certificate usage
		/// </summary>
		public TlsaCertificateUsage CertificateUsage { get; private set; }

		/// <summary>
		///   The selector
		/// </summary>
		public TlsaSelector Selector { get; private set; }

		/// <summary>
		///   The matching type
		/// </summary>
		public TlsaMatchingType MatchingType { get; private set; }

		/// <summary>
		///   The certificate association data
		/// </summary>
		public byte[] CertificateAssociation { get; private set; }

		internal TlsaRecord() {}

		/// <summary>
		///   Creates a new instance of the NIdRecord class
		/// </summary>
		/// <param name="name"> Domain name of the host </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="certificateUsage"></param>
		/// <param name="selector"></param>
		/// <param name="matchingType"></param>
		/// <param name="certificateAssociation"></param>
		public TlsaRecord(string name, int timeToLive, TlsaCertificateUsage certificateUsage, TlsaSelector selector, TlsaMatchingType matchingType, byte[] certificateAssociation)
			: base(name, RecordType.Tlsa, RecordClass.INet, timeToLive)
		{
			CertificateUsage = certificateUsage;
			Selector = selector;
			MatchingType = matchingType;
			CertificateAssociation = certificateAssociation ?? new byte[] { };
		}

		internal override void ParseRecordData(byte[] resultData, int startPosition, int length)
		{
			CertificateUsage = (TlsaCertificateUsage) resultData[startPosition++];
			Selector = (TlsaSelector) resultData[startPosition++];
			MatchingType = (TlsaMatchingType) resultData[startPosition++];
			CertificateAssociation = DnsMessageBase.ParseByteData(resultData, ref startPosition, length - 3);
		}

		internal override string RecordDataToString()
		{
			return (byte) CertificateUsage + " " + (byte) Selector + " " + (byte) MatchingType + " " + String.Join(String.Empty, CertificateAssociation.Select(x => x.ToString("X2")).ToArray());
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 3 + CertificateAssociation.Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			messageData[currentPosition++] = (byte) CertificateUsage;
			messageData[currentPosition++] = (byte) Selector;
			messageData[currentPosition++] = (byte) MatchingType;
			DnsMessageBase.EncodeByteArray(messageData, ref currentPosition, CertificateAssociation);
		}
	}
}