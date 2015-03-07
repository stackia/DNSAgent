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
	///   <para>Update lease option</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://files.dns-sd.org/draft-sekar-dns-ul.txt">draft-sekar-dns-ul</see>
	///   </para>
	/// </summary>
	public class UpdateLeaseOption : EDnsOptionBase
	{
		/// <summary>
		///   Desired lease (request) or granted lease (response)
		/// </summary>
		public TimeSpan LeaseTime { get; private set; }

		internal UpdateLeaseOption()
			: base(EDnsOptionType.UpdateLease) {}

		/// <summary>
		///   Creates a new instance of the UpdateLeaseOption class
		/// </summary>
		public UpdateLeaseOption(TimeSpan leaseTime)
			: this()
		{
			LeaseTime = leaseTime;
		}

		internal override void ParseData(byte[] resultData, int startPosition, int length)
		{
			LeaseTime = TimeSpan.FromSeconds(DnsMessageBase.ParseInt(resultData, ref startPosition));
		}

		internal override ushort DataLength
		{
			get { return 4; }
		}

		internal override void EncodeData(byte[] messageData, ref int currentPosition)
		{
			DnsMessageBase.EncodeInt(messageData, ref currentPosition, (int) LeaseTime.TotalSeconds);
		}
	}
}