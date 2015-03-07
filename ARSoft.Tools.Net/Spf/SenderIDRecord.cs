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
using System.Text.RegularExpressions;

namespace ARSoft.Tools.Net.Spf
{
	/// <summary>
	///   <para>Parsed instance of the textual representation of a SenderID record</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc4406">RFC 4406</see>
	///   </para>
	/// </summary>
	public class SenderIDRecord : SpfRecordBase
	{
		/// <summary>
		///   Version of the SenderID record.
		/// </summary>
		public int Version { get; set; }

		/// <summary>
		///   Minor version of the SenderID record
		/// </summary>
		public int MinorVersion { get; set; }

		/// <summary>
		///   List of Scopes of the SenderID record
		/// </summary>
		public List<SenderIDScope> Scopes { get; set; }

		/// <summary>
		///   Returns the textual representation of the SenderID record
		/// </summary>
		/// <returns> Textual representation </returns>
		public override string ToString()
		{
			StringBuilder res = new StringBuilder();

			if (Version == 1)
			{
				res.Append("v=spf1");
			}
			else
			{
				res.Append("v=spf");
				res.Append(Version);
				res.Append(".");
				res.Append(MinorVersion);
				res.Append("/");
				res.Append(String.Join(",", Scopes.Where(s => s != SenderIDScope.Unknown).Select(s => EnumHelper<SenderIDScope>.ToString(s).ToLower()).ToArray()));
			}

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
		///   Checks, whether a given string starts with a correct SenderID prefix of a given scope
		/// </summary>
		/// <param name="s"> Textual representation to check </param>
		/// <param name="scope"> Scope, which should be matched </param>
		/// <returns> true in case of correct prefix </returns>
		public static bool IsSenderIDRecord(string s, SenderIDScope scope)
		{
			if (String.IsNullOrEmpty(s))
				return false;

			string[] terms = s.Split(new[] { ' ' }, 2);

			if (terms.Length < 2)
				return false;

			int version;
			int minor;
			List<SenderIDScope> scopes;
			if (!TryParsePrefix(terms[0], out version, out minor, out scopes))
			{
				return false;
			}

			if ((version == 1) && ((scope == SenderIDScope.MFrom) || (scope == SenderIDScope.Pra)))
			{
				return true;
			}
			else
			{
				return scopes.Contains(scope);
			}
		}

		private static bool TryParsePrefix(string prefix, out int version, out int minor, out List<SenderIDScope> scopes)
		{
			Regex regex = new Regex(@"^v=spf((?<version>1)|(?<version>2)\.(?<minor>\d)/(?<scopes>(([a-z0-9]+,)*[a-z0-9]+)))$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
			Match match = regex.Match(prefix);
			if (!match.Success)
			{
				version = 0;
				minor = 0;
				scopes = null;

				return false;
			}

			version = Int32.Parse(match.Groups["version"].Value);
			minor = Int32.Parse("0" + match.Groups["minor"].Value);
			scopes = match.Groups["scopes"].Value.Split(',').Select(t => EnumHelper<SenderIDScope>.Parse(t, true, SenderIDScope.Unknown)).ToList();

			return true;
		}

		/// <summary>
		///   Tries to parse the textual representation of a SenderID record
		/// </summary>
		/// <param name="s"> Textual representation to check </param>
		/// <param name="value"> Parsed SenderID record in case of successful parsing </param>
		/// <returns> true in case of successful parsing </returns>
		public static bool TryParse(string s, out SenderIDRecord value)
		{
			if (String.IsNullOrEmpty(s))
			{
				value = null;
				return false;
			}

			string[] terms = s.Split(new[] { ' ' }, StringSplitOptions.RemoveEmptyEntries);

			if (terms.Length < 1)
			{
				value = null;
				return false;
			}

			int version;
			int minor;
			List<SenderIDScope> scopes;
			if (!TryParsePrefix(terms[0], out version, out minor, out scopes))
			{
				value = null;
				return false;
			}

			List<SpfTerm> parsedTerms;
			if (TryParseTerms(terms, out parsedTerms))
			{
				value =
					new SenderIDRecord
					{
						Version = version,
						MinorVersion = minor,
						Scopes = scopes,
						Terms = parsedTerms
					};
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