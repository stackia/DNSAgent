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
	///   Base class of a SPF or SenderID record
	/// </summary>
	public class SpfRecordBase
	{
		/// <summary>
		///   Modifiers and mechanisms of a record
		/// </summary>
		public List<SpfTerm> Terms { get; set; }

		protected static bool TryParseTerms(string[] terms, out List<SpfTerm> parsedTerms)
		{
			parsedTerms = new List<SpfTerm>(terms.Length - 1);

			for (int i = 1; i < terms.Length; i++)
			{
				SpfTerm term;
				if (SpfTerm.TryParse(terms[i], out term))
				{
					parsedTerms.Add(term);
				}
				else
				{
					parsedTerms = null;
					return false;
				}
			}

			return true;
		}
	}
}