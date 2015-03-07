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
using ARSoft.Tools.Net.Dns;

namespace ARSoft.Tools.Net.Spf
{
	/// <summary>
	///   Validator for SPF records
	/// </summary>
	public class SpfValidator : ValidatorBase<SpfRecord>
	{
		protected override bool TryLoadRecords(string domain, out SpfRecord record, out SpfQualifier errorResult)
		{
			if (!TryLoadRecords(domain, RecordType.Spf, out record, out errorResult))
			{
				return (errorResult == SpfQualifier.None) && TryLoadRecords(domain, RecordType.Txt, out record, out errorResult);
			}
			else
			{
				return true;
			}
		}

		private bool TryLoadRecords(string domain, RecordType recordType, out SpfRecord record, out SpfQualifier errorResult)
		{
			DnsMessage dnsMessage = ResolveDns(domain, recordType);
			if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
			{
				record = default(SpfRecord);
				errorResult = SpfQualifier.TempError;
				return false;
			}

			var spfTextRecords =
				dnsMessage.AnswerRecords
				          .Where(r => r.RecordType == recordType)
				          .Cast<ITextRecord>()
				          .Select(r => r.TextData)
				          .Where(SpfRecord.IsSpfRecord).ToList();

			if (spfTextRecords.Count == 0)
			{
				record = default(SpfRecord);
				errorResult = SpfQualifier.None;
				return false;
			}
			else if ((spfTextRecords.Count > 1) || !SpfRecord.TryParse(spfTextRecords[0], out record))
			{
				record = default(SpfRecord);
				errorResult = SpfQualifier.PermError;
				return false;
			}
			else
			{
				errorResult = default(SpfQualifier);
				return true;
			}
		}
	}
}