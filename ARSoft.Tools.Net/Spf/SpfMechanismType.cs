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

namespace ARSoft.Tools.Net.Spf
{
	/// <summary>
	///   Type of spf mechanism
	/// </summary>
	public enum SpfMechanismType
	{
		/// <summary>
		///   Unknown mechanism
		/// </summary>
		Unknown,

		/// <summary>
		///   All mechanism, matches always
		/// </summary>
		All,

		/// <summary>
		///   IP4 mechanism, matches if ip address (IPv4) is within the given network
		/// </summary>
		Ip4,

		/// <summary>
		///   IP6 mechanism, matches if ip address (IPv6) is within the given network
		/// </summary>
		Ip6,

		/// <summary>
		///   A mechanism, matches if the ip address is the target of a hostname lookup for the given domain
		/// </summary>
		A,

		/// <summary>
		///   MX mechanism, matches if the ip address is a mail exchanger for the given domain
		/// </summary>
		Mx,

		/// <summary>
		///   PTR mechanism, matches if a correct reverse mapping exists
		/// </summary>
		Ptr,

		/// <summary>
		///   EXISTS mechanism, matches if the given domain exists
		/// </summary>
		Exist,

		/// <summary>
		///   INCLUDE mechanism, triggers a recursive evaluation
		/// </summary>
		Include,
	}
}