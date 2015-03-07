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
	///   Represents a single term of a SPF record
	/// </summary>
	public class SpfTerm
	{
		internal static bool TryParse(string s, out SpfTerm value)
		{
			if (String.IsNullOrEmpty(s))
			{
				value = null;
				return false;
			}

			#region Parse Mechanism
			Regex regex = new Regex(@"^(\s)*(?<qualifier>[~+?-]?)(?<type>[a-z0-9]+)(:(?<domain>[^/]+))?(/(?<prefix>[0-9]+)(/(?<prefix6>[0-9]+))?)?(\s)*$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
			Match match = regex.Match(s);
			if (match.Success)
			{
				SpfMechanism mechanism = new SpfMechanism();

				switch (match.Groups["qualifier"].Value)
				{
					case "+":
						mechanism.Qualifier = SpfQualifier.Pass;
						break;
					case "-":
						mechanism.Qualifier = SpfQualifier.Fail;
						break;
					case "~":
						mechanism.Qualifier = SpfQualifier.SoftFail;
						break;
					case "?":
						mechanism.Qualifier = SpfQualifier.Neutral;
						break;

					default:
						mechanism.Qualifier = SpfQualifier.Pass;
						break;
				}

				SpfMechanismType type;
				mechanism.Type = EnumHelper<SpfMechanismType>.TryParse(match.Groups["type"].Value, true, out type) ? type : SpfMechanismType.Unknown;

				mechanism.Domain = match.Groups["domain"].Value;

				string tmpPrefix = match.Groups["prefix"].Value;
				int prefix;
				if (!String.IsNullOrEmpty(tmpPrefix) && Int32.TryParse(tmpPrefix, out prefix))
				{
					mechanism.Prefix = prefix;
				}

				tmpPrefix = match.Groups["prefix6"].Value;
				if (!String.IsNullOrEmpty(tmpPrefix) && Int32.TryParse(tmpPrefix, out prefix))
				{
					mechanism.Prefix6 = prefix;
				}

				value = mechanism;
				return true;
			}
			#endregion

			#region Parse Modifier
			regex = new Regex(@"^(\s)*(?<type>[a-z]+)=(?<domain>[^\s]+)(\s)*$", RegexOptions.Compiled | RegexOptions.IgnoreCase);
			match = regex.Match(s);
			if (match.Success)
			{
				SpfModifier modifier = new SpfModifier();

				SpfModifierType type;
				modifier.Type = EnumHelper<SpfModifierType>.TryParse(match.Groups["type"].Value, true, out type) ? type : SpfModifierType.Unknown;
				modifier.Domain = match.Groups["domain"].Value;

				value = modifier;
				return true;
			}
			#endregion

			value = null;
			return false;
		}
	}
}