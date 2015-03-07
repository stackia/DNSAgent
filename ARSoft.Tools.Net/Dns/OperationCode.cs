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
	///   Operation code of a dns query
	/// </summary>
	public enum OperationCode : ushort
	{
		/// <summary>
		///   <para>Normal query</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		Query = 0,

		/// <summary>
		///   <para>Inverse query</para>
		///   <para>
		///     Obsoleted by
		///     <see cref="!:http://tools.ietf.org/html/rfc3425">RFC 3425</see>
		///   </para>
		/// </summary>
		[Obsolete]
		InverseQuery = 1,

		/// <summary>
		///   <para>Server status request</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1035">RFC 1035</see>
		///   </para>
		/// </summary>
		Status = 2,

		/// <summary>
		///   <para>Notify of zone change</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc1996">RFC 1996</see>
		///   </para>
		/// </summary>
		Notify = 4,

		/// <summary>
		///   <para>Dynamic update</para>
		///   <para>
		///     Defined in
		///     <see cref="!:http://tools.ietf.org/html/rfc2136">RFC 2136</see>
		///   </para>
		/// </summary>
		Update = 5,
	}
}