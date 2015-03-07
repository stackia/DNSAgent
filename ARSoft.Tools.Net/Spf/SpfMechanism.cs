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
	///   Represents a single mechanism term in a SPF record
	/// </summary>
	public class SpfMechanism : SpfTerm
	{
		/// <summary>
		///   Qualifier of the mechanism
		/// </summary>
		public SpfQualifier Qualifier { get; set; }

		/// <summary>
		///   Type of the mechanism
		/// </summary>
		public SpfMechanismType Type { get; set; }

		/// <summary>
		///   Domain part of the mechanism
		/// </summary>
		public string Domain { get; set; }

		/// <summary>
		///   IPv4 prefix of the mechanism
		/// </summary>
		public int? Prefix { get; set; }

		/// <summary>
		///   IPv6 prefix of the mechanism
		/// </summary>
		public int? Prefix6 { get; set; }

		/// <summary>
		///   Returns the textual representation of a mechanism term
		/// </summary>
		/// <returns> Textual representation </returns>
		public override string ToString()
		{
			StringBuilder res = new StringBuilder();

			switch (Qualifier)
			{
				case SpfQualifier.Fail:
					res.Append("-");
					break;
				case SpfQualifier.SoftFail:
					res.Append("~");
					break;
				case SpfQualifier.Neutral:
					res.Append("?");
					break;
			}

			res.Append(EnumHelper<SpfMechanismType>.ToString(Type).ToLower());

			if (!String.IsNullOrEmpty(Domain))
			{
				res.Append(":");
				res.Append(Domain);
			}

			if (Prefix.HasValue)
			{
				res.Append("/");
				res.Append(Prefix.Value);
			}

			if (Prefix6.HasValue)
			{
				res.Append("//");
				res.Append(Prefix6.Value);
			}

			return res.ToString();
		}
	}
}