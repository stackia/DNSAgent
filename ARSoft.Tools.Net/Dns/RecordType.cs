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
	///   Type of record
	/// </summary>
	public enum RecordType : ushort
	{
		/// <summary>
		///   Invalid record type
		/// </summary>
		Invalid = 0,

		/// <summary>
		///   <para>Host address</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		A = 1,

		/// <summary>
		///   <para>Authoritatitve name server</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		Ns = 2,

		/// <summary>
		///   <para>Mail destination</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		[Obsolete]
		Md = 3,

		/// <summary>
		///   <para>Mail forwarder</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		[Obsolete]
		Mf = 4,

		/// <summary>
		///   <para>Canonical name for an alias</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		CName = 5,

		/// <summary>
		///   <para>Start of zone of authority</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		Soa = 6,

		/// <summary>
		///   <para>Mailbox domain name</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///     - Experimental
		///   </para>
		/// </summary>
		Mb = 7, // not supported yet

		/// <summary>
		///   <para>Mail group member</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///     - Experimental
		///   </para>
		/// </summary>
		Mg = 8, // not supported yet

		/// <summary>
		///   <para>Mail rename domain name</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///     - Experimental
		///   </para>
		/// </summary>
		Mr = 9, // not supported yet

		/// <summary>
		///   <para>Null record</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///     - Experimental
		///   </para>
		/// </summary>
		Null = 10, // not supported yet

		/// <summary>
		///   <para>Well known services</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		Wks = 11,

		/// <summary>
		///   <para>Domain name pointer</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		Ptr = 12,

		/// <summary>
		///   <para>Host information</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		HInfo = 13,

		/// <summary>
		///   <para>Mailbox or mail list information</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		MInfo = 14, // not supported yet

		/// <summary>
		///   <para>Mail exchange</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		Mx = 15,

		/// <summary>
		///   <para>Text strings</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		Txt = 16,

		/// <summary>
		///   <para>Responsible person</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1183">RFC 1183</see>
		///   </para>
		/// </summary>
		Rp = 17,

		/// <summary>
		///   <para>AFS data base location</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1183">RFC 1183</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc5864">RFC 5864</see>
		///   </para>
		/// </summary>
		Afsdb = 18,

		/// <summary>
		///   <para>X.25 PSDN address</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1183">RFC 1183</see>
		///   </para>
		/// </summary>
		X25 = 19,

		/// <summary>
		///   <para>ISDN address</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1183">RFC 1183</see>
		///   </para>
		/// </summary>
		Isdn = 20,

		/// <summary>
		///   <para>Route through</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1183">RFC 1183</see>
		///   </para>
		/// </summary>
		Rt = 21,

		/// <summary>
		///   <para>NSAP address, NSAP style A record</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1706">RFC 1706</see>
		///   </para>
		/// </summary>
		Nsap = 22,

		/// <summary>
		///   <para>Domain name pointer, NSAP style</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1348">RFC 1348</see>
		///     ,
		///     <see cref="!:http://tools.ietf.org/html/rfc1637">RFC 1637</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc1706">RFC 1706</see>
		///   </para>
		/// </summary>
		NsapPtr = 23, // not supported yet

		/// <summary>
		///   <para>Security signature</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
		///     ,
		///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
		///     ,
		///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc2931">RFC 2931</see>
		///   </para>
		/// </summary>
		Sig = 24,

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
		Key = 25,

		/// <summary>
		///   <para>X.400 mail mapping information</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc2163">RFC 2163</see>
		///   </para>
		/// </summary>
		Px = 26,

		/// <summary>
		///   <para>Geographical position</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1712">RFC 1712</see>
		///   </para>
		/// </summary>
		GPos = 27,

		/// <summary>
		///   <para>IPv6 address</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc3596">RFC 3596</see>
		///   </para>
		/// </summary>
		Aaaa = 28,

		/// <summary>
		///   <para>Location information</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1876">RFC 1876</see>
		///   </para>
		/// </summary>
		Loc = 29,

		/// <summary>
		///   <para>Next domain</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc2535">RFC 2535</see>
		///   </para>
		/// </summary>
		[Obsolete]
		Nxt = 30,

		/// <summary>
		///   <para>Endpoint identifier</para>
		///   <para>Defined by Michael Patton, &lt;map@bbn.com&gt;, June 1995</para>
		/// </summary>
		Eid = 31, // not supported yet

		/// <summary>
		///   <para>Nimrod locator</para>
		///   <para>Defined by Michael Patton, &lt;map@bbn.com&gt;, June 1995</para>
		/// </summary>
		NimLoc = 32, // not supported yet

		/// <summary>
		///   <para>Server selector</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc2782">RFC 2782</see>
		///   </para>
		/// </summary>
		Srv = 33,

		/// <summary>
		///   <para>ATM address</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://broadband-forum.org/ftp/pub/approved-specs/af-saa-0069.000.pdf">ATM Forum Technical Committee, "ATM Name System, V2.0"</see>
		///   </para>
		/// </summary>
		AtmA = 34, // not supported yet

		/// <summary>
		///   <para>Naming authority pointer</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc2915">RFC 2915</see>
		///     ,
		///     <see cref="!:http://tools.ietf.org/html/rfc2168">RFC 2168</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc3403">RFC 3403</see>
		///   </para>
		/// </summary>
		Naptr = 35,

		/// <summary>
		///   <para>Key exchanger</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc2230">RFC 2230</see>
		///   </para>
		/// </summary>
		Kx = 36,

		/// <summary>
		///   <para>Certificate storage</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4398">RFC 4398</see>
		///   </para>
		/// </summary>
		Cert = 37,

		/// <summary>
		///   <para>A6</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc3226">RFC 3226</see>
		///     ,
		///     <see cref="!:http://tools.ietf.org/html/rfc2874">RFC 2874</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc6563">RFC 2874</see>
		///     - Experimental
		///   </para>
		/// </summary>
		[Obsolete]
		A6 = 38,

		/// <summary>
		///   <para>DNS Name Redirection</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6672">RFC 6672</see>
		///   </para>
		/// </summary>
		DName = 39,

		/// <summary>
		///   <para>SINK</para>
		///   <para>Defined by Donald E. Eastlake, III &lt;d3e3e3@gmail.com&gt;, January 1995, November 1997</para>
		/// </summary>
		Sink = 40, // not supported yet

		/// <summary>
		///   <para>OPT</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6891">RFC 6891</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc3225">RFC 3658</see>
		///   </para>
		/// </summary>
		Opt = 41,

		/// <summary>
		///   <para>Address prefixes</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc3123">RFC 3123</see>
		///   </para>
		/// </summary>
		Apl = 42,

		/// <summary>
		///   <para>Delegation signer</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc3658">RFC 3658</see>
		///   </para>
		/// </summary>
		Ds = 43,

		/// <summary>
		///   <para>SSH key fingerprint</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4255">RFC 4255</see>
		///   </para>
		/// </summary>
		SshFp = 44,

		/// <summary>
		///   <para>IPsec key storage</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4025">RFC 4025</see>
		///   </para>
		/// </summary>
		IpSecKey = 45,

		/// <summary>
		///   <para>Record signature</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
		///   </para>
		/// </summary>
		RrSig = 46,

		/// <summary>
		///   <para>Next owner</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
		///   </para>
		/// </summary>
		NSec = 47,

		/// <summary>
		///   <para>DNS Key</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4034">RFC 4034</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc3755">RFC 3755</see>
		///   </para>
		/// </summary>
		DnsKey = 48,

		/// <summary>
		///   <para>Dynamic Host Configuration Protocol (DHCP) Information</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4701">RFC 4701</see>
		///   </para>
		/// </summary>
		Dhcid = 49,

		/// <summary>
		///   <para>Hashed next owner</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5155">RFC 5155</see>
		///   </para>
		/// </summary>
		NSec3 = 50,

		/// <summary>
		///   <para>Hashed next owner parameter</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5155">RFC 5155</see>
		///   </para>
		/// </summary>
		NSec3Param = 51,

		/// <summary>
		///   <para>TLSA</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6698">RFC 6698</see>
		///   </para>
		/// </summary>
		Tlsa = 52,

		/// <summary>
		///   <para>Host identity protocol</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc5205">RFC 5205</see>
		///   </para>
		/// </summary>
		Hip = 55,

		/// <summary>
		///   <para>NINFO</para>
		///   <para>Defined by Jim Reid, &lt;jim@telnic.org&gt;, 21 January 2008</para>
		/// </summary>
		NInfo = 56, // not supported yet

		/// <summary>
		///   <para>RKEY</para>
		///   <para>Defined by Jim Reid, &lt;jim@telnic.org&gt;, 21 January 2008</para>
		/// </summary>
		RKey = 57, // not supported yet

		/// <summary>
		///   <para>Trust anchor link</para>
		///   <para>Defined by Wouter Wijngaards, &lt;wouter@nlnetlabs.nl&gt;, 2010-02-17</para>
		/// </summary>
		TALink = 58, // not supported yet

		/// <summary>
		///   <para>Child DS</para>
		///   <para>Defined by George Barwood, &lt;george.barwood@blueyonder.co.uk&gt;, 06 June 2011</para>
		/// </summary>
		CDS = 59, // not supported yet

		/// <summary>
		///   <para>Sender Policy Framework</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4408">RFC 4408</see>
		///   </para>
		/// </summary>
		Spf = 99,

		/// <summary>
		///   <para>UINFO</para>
		///   <para>IANA-Reserved</para>
		/// </summary>
		UInfo = 100, // not supported yet

		/// <summary>
		///   <para>UID</para>
		///   <para>IANA-Reserved</para>
		/// </summary>
		UId = 101, // not supported yet

		/// <summary>
		///   <para>GID</para>
		///   <para>IANA-Reserved</para>
		/// </summary>
		Gid = 102, // not supported yet

		/// <summary>
		///   <para>UNSPEC</para>
		///   <para>IANA-Reserved</para>
		/// </summary>
		Unspec = 103, // not supported yet

		/// <summary>
		///   <para>NID</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6742">RFC 6742</see>
		///   </para>
		/// </summary>
		NId = 104,

		/// <summary>
		///   <para>L32</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6742">RFC 6742</see>
		///   </para>
		/// </summary>
		L32 = 105,

		/// <summary>
		///   <para>L64</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6742">RFC 6742</see>
		///   </para>
		/// </summary>
		L64 = 106,

		/// <summary>
		///   <para>LP</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6742">RFC 6742</see>
		///   </para>
		/// </summary>
		LP = 107,

		/// <summary>
		///   <para>EUI-48 address</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc7043">RFC 7043</see>
		///   </para>
		/// </summary>
		Eui48 = 108,

		/// <summary>
		///   <para>EUI-64 address</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc7043">RFC 7043</see>
		///   </para>
		/// </summary>
		Eui64 = 109,

		/// <summary>
		///   <para>Transaction key</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc2930">RFC 2930</see>
		///   </para>
		/// </summary>
		TKey = 249,

		/// <summary>
		///   <para>Transaction signature</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc2845">RFC 2845</see>
		///   </para>
		/// </summary>
		TSig = 250,

		/// <summary>
		///   <para>Incremental zone transfer</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1995">RFC 1995</see>
		///   </para>
		/// </summary>
		Ixfr = 251,

		/// <summary>
		///   <para>Request transfer of entire zone</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///     and
		///     <see cref="!:http://tools.ietf.org/html/rfc5936">RFC 5936</see>
		///   </para>
		/// </summary>
		Axfr = 252,

		/// <summary>
		///   <para>Request mailbox related recors</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		MailB = 253,

		/// <summary>
		///   <para>Request of mail agent records</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		[Obsolete]
		MailA = 254,

		/// <summary>
		///   <para>Request of all records</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		Any = 255,

		/// <summary>
		///   <para>URI</para>
		///   <para>Defined by Patrik Faltstrom, &lt;paf@cisco.com&gt;, 22 February 2011</para>
		/// </summary>
		Uri = 256, // not supported yet

		/// <summary>
		///   <para>Certification authority auhtorization</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc6844">RFC 6844</see>
		///   </para>
		/// </summary>
		CAA = 257,

		/// <summary>
		///   <para>DNSSEC trust authorities</para>
		///   <para>Defined by Sam Weiler, &lt;weiler+iana@tislabs.com&gt;</para>
		/// </summary>
		Ta = 32768, // not supported yet

		/// <summary>
		///   <para>DNSSEC lookaside validation</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc4431">RFC 4431</see>
		///   </para>
		/// </summary>
		Dlv = 32769,
	}
}