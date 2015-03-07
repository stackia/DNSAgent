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
	///   DNSSEC algorithm type
	/// </summary>
	public enum DnsSecAlgorithm : byte
	{
		/// <summary>
		///   <para>RSA MD5</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
		///   </para>
		/// </summary>
		RsaMd5 = 1,

		/// <summary>
		///   <para>Diffie Hellman</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc2539">RFC 2539</see>
		///   </para>
		/// </summary>
		DiffieHellman = 2,

		/// <summary>
		///   <para>DSA/SHA-1</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
		///   </para>
		/// </summary>
		DsaSha1 = 3,

		/// <summary>
		///   <para>Elliptic curves</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc">RFC</see>
		///   </para>
		/// </summary>
		EllipticCurve = 4,

		/// <summary>
		///   <para>RSA/SHA-1</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
		///   </para>
		/// </summary>
		RsaSha1 = 5,

		/// <summary>
		///   <para>DSA/SHA-1 using NSEC3 hashs</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5155">RFC 5155</see>
		///   </para>
		/// </summary>
		DsaNsec3Sha1 = 6,

		/// <summary>
		///   <para>RSA/SHA-1 using NSEC3 hashs</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5155">RFC 5155</see>
		///   </para>
		/// </summary>
		RsaSha1Nsec3Sha1 = 7,

		/// <summary>
		///   <para>RSA/SHA-256</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5702">RFC 5702</see>
		///   </para>
		/// </summary>
		RsaSha256 = 8,

		/// <summary>
		///   <para>RSA/SHA-512</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5702">RFC 5702</see>
		///   </para>
		/// </summary>
		RsaSha512 = 10,

		/// <summary>
		///   <para>GOST Signature</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5933">RFC 5933</see>
		///   </para>
		/// </summary>
		EccGost = 12,

		/// <summary>
		///   <para>Indirect</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
		///   </para>
		/// </summary>
		Indirect = 252, // RFC4034

		/// <summary>
		///   <para>Private key using named algorithm</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
		///   </para>
		/// </summary>
		PrivateDns = 253,

		/// <summary>
		///   <para>Private key using algorithm object identifier</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
		///   </para>
		/// </summary>
		PrivateOid = 254,
	}
}