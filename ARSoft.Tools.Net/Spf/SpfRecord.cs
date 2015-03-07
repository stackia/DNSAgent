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
	///   <para>Parsed instance of the textual representation of a SPF record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc4408">RFC 4408</see>
	///   </para>
	/// </summary>
	public class SpfRecord : SpfRecordBase
	{
		/// <summary>
		///   Returns the textual representation of a SPF record
		/// </summary>
		/// <returns> Textual representation </returns>
		public override string ToString()
		{
			StringBuilder res = new StringBuilder();
			res.Append("v=spf1");

			if ((Terms != null) && (Terms.Count > 0))
			{
				foreach (SpfTerm term in Terms)
				{
					SpfModifier modifier = term as SpfModifier;
					if ((modifier == null) || (modifier.Type != SpfModifierType.Unknown))
					{
						res.Append(" ");
						res.Append(term.ToString());
					}
				}
			}

			return res.ToString();
		}

		/// <summary>
		///   Checks, whether a given string starts with a correct SPF prefix
		/// </summary>
		/// <param name="s"> Textual representation to check </param>
		/// <returns> true in case of correct prefix </returns>
		public static bool IsSpfRecord(string s)
		{
			return !String.IsNullOrEmpty(s) && s.StartsWith("v=spf1 ");
		}

		/// <summary>
		///   Tries to parse the textual representation of a SPF string
		/// </summary>
		/// <param name="s"> Textual representation to check </param>
		/// <param name="value"> Parsed spf record in case of successful parsing </param>
		/// <returns> true in case of successful parsing </returns>
		public static bool TryParse(string s, out SpfRecord value)
		{
			if (!IsSpfRecord(s))
			{
				value = null;
				return false;
			}

			string[] terms = s.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

			List<SpfTerm> parsedTerms;
			if (TryParseTerms(terms, out parsedTerms))
			{
				value = new SpfRecord { Terms = parsedTerms };
				return true;
			}
			else
			{
				value = null;
				return false;
			}
		}
	}
}