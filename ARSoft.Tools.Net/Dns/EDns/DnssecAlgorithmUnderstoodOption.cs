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
	///   <para>DNSSEC Algorithm Understood option</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc6975">RFC 6975</see>
	///   </para>
	/// </summary>
	public class DnssecAlgorithmUnderstoodOption : EDnsOptionBase
	{
		/// <summary>
		///   List of Algorithms
		/// </summary>
		public List<DnsSecAlgorithm> Algorithms { get; private set; }

		internal DnssecAlgorithmUnderstoodOption()
			: base(EDnsOptionType.DnssecAlgorithmUnderstood) {}

		/// <summary>
		///   Creates a new instance of the DnssecAlgorithmUnderstoodOption class
		/// </summary>
		/// <param name="algorithms">The list of algorithms</param>
		public DnssecAlgorithmUnderstoodOption(List<DnsSecAlgorithm> algorithms)
			: this()
		{
			Algorithms = algorithms;
		}

		internal override void ParseData(byte[] resultData, int startPosition, int length)
		{
			Algorithms = new List<DnsSecAlgorithm>(length);
			for (int i = 0; i < length; i++)
			{
				Algorithms.Add((DnsSecAlgorithm) resultData[startPosition++]);
			}
		}

		internal override ushort DataLength
		{
			get { return (ushort) ((Algorithms == null) ? 0 : Algorithms.Count); }
		}

		internal override void EncodeData(byte[] messageData, ref int currentPosition)
		{
			foreach (var algorithm in Algorithms)
			{
				messageData[currentPosition++] = (byte) algorithm;
			}
		}
	}
}