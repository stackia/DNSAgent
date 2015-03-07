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
	///   Represents a single modifier term in a SPF record
	/// </summary>
	public class SpfModifier : SpfTerm
	{
		/// <summary>
		///   Type of the modifier
		/// </summary>
		public SpfModifierType Type { get; set; }

		/// <summary>
		///   Domain part of the modifier
		/// </summary>
		public string Domain { get; set; }

		/// <summary>
		///   Returns the textual representation of a modifier term
		/// </summary>
		/// <returns> Textual representation </returns>
		public override string ToString()
		{
			StringBuilder res = new StringBuilder();

			res.Append(EnumHelper<SpfModifierType>.ToString(Type).ToLower());
			res.Append("=");
			res.Append(Domain);

			return res.ToString();
		}
	}
}