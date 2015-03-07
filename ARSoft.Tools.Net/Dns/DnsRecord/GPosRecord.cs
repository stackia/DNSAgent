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
using System.Globalization;
using System.Linq;
using System.Text;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   <para>Geographical position</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc1712">RFC 1712</see>
	///   </para>
	/// </summary>
	public class GPosRecord : DnsRecordBase
	{
		/// <summary>
		///   Longitude of the geographical position
		/// </summary>
		public double Longitude { get; private set; }

		/// <summary>
		///   Latitude of the geographical position
		/// </summary>
		public double Latitude { get; private set; }

		/// <summary>
		///   Altitude of the geographical position
		/// </summary>
		public double Altitude { get; private set; }

		internal GPosRecord() {}

		/// <summary>
		///   Creates a new instance of the GPosRecord class
		/// </summary>
		/// <param name="name"> Name of the record </param>
		/// <param name="timeToLive"> Seconds the record should be cached at most </param>
		/// <param name="longitude"> Longitude of the geographical position </param>
		/// <param name="latitude"> Latitude of the geographical position </param>
		/// <param name="altitude"> Altitude of the geographical position </param>
		public GPosRecord(string name, int timeToLive, double longitude, double latitude, double altitude)
			: base(name, RecordType.GPos, RecordClass.INet, timeToLive)
		{
			Longitude = longitude;
			Latitude = latitude;
			Altitude = altitude;
		}

		internal override void ParseRecordData(byte[] resultData, int currentPosition, int length)
		{
			Longitude = Double.Parse(DnsMessageBase.ParseText(resultData, ref currentPosition), CultureInfo.InvariantCulture);
			Latitude = Double.Parse(DnsMessageBase.ParseText(resultData, ref currentPosition), CultureInfo.InvariantCulture);
			Altitude = Double.Parse(DnsMessageBase.ParseText(resultData, ref currentPosition), CultureInfo.InvariantCulture);
		}

		internal override string RecordDataToString()
		{
			return Longitude.ToString(CultureInfo.InvariantCulture)
			       + " " + Latitude.ToString(CultureInfo.InvariantCulture)
			       + " " + Altitude.ToString(CultureInfo.InvariantCulture);
		}

		protected internal override int MaximumRecordDataLength
		{
			get { return 3 + Longitude.ToString().Length + Latitude.ToString().Length + Altitude.ToString().Length; }
		}

		protected internal override void EncodeRecordData(byte[] messageData, int offset, ref int currentPosition, Dictionary<string, ushort> domainNames)
		{
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, Longitude.ToString(CultureInfo.InvariantCulture));
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, Latitude.ToString(CultureInfo.InvariantCulture));
			DnsMessageBase.EncodeTextBlock(messageData, ref currentPosition, Altitude.ToString(CultureInfo.InvariantCulture));
		}
	}
}