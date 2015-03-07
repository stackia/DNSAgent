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
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;
using ARSoft.Tools.Net.Dns;

namespace ARSoft.Tools.Net.Spf
{
	/// <summary>
	///   Base implementation of a validator for SPF and SenderID records
	/// </summary>
	/// <typeparam name="T"> Type of the record </typeparam>
	public abstract class ValidatorBase<T>
		where T : SpfRecordBase
	{
		/// <summary>
		///   Domain name which was used in HELO/EHLO
		/// </summary>
		public string HeloDomain { get; set; }

		/// <summary>
		///   IP address of the computer validating the record
		///   <para>Default is the first IP the computer</para>
		/// </summary>
		public IPAddress LocalIP { get; set; }

		/// <summary>
		///   Name of the computer validating the record
		///   <para>Default is the computer name</para>
		/// </summary>
		public string LocalDomain { get; set; }

		private int _dnsLookupLimit = 20;

		/// <summary>
		///   The maximum number of DNS lookups allowed
		///   <para>Default is 20</para>
		/// </summary>
		public int DnsLookupLimit
		{
			get { return _dnsLookupLimit; }
			set { _dnsLookupLimit = value; }
		}

		private readonly Dictionary<string, DnsMessage> _dnsCache = new Dictionary<string, DnsMessage>();

		private int LookupCount
		{
			get { return _dnsCache.Count; }
		}

		protected abstract bool TryLoadRecords(string domain, out T record, out SpfQualifier errorResult);

		/// <summary>
		///   Validates the record(s)
		/// </summary>
		/// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
		/// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
		/// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
		/// <returns> The result of the evaluation </returns>
		public SpfQualifier CheckHost(IPAddress ip, string domain, string sender)
		{
			try
			{
				string explanation;
				return CheckHostInternal(ip, sender, domain, false, out explanation);
			}
			finally
			{
				_dnsCache.Clear();
			}
		}

		/// <summary>
		///   Validates the record(s)
		/// </summary>
		/// <param name="ip"> The IP address of the SMTP client that is emitting the mail </param>
		/// <param name="domain"> The domain portion of the "MAIL FROM" or "HELO" identity </param>
		/// <param name="sender"> The "MAIL FROM" or "HELO" identity </param>
		/// <param name="explanation"> A explanation in case of result Fail </param>
		/// <returns> The result of the evaluation </returns>
		public SpfQualifier CheckHost(IPAddress ip, string sender, string domain, out string explanation)
		{
			try
			{
				return CheckHostInternal(ip, sender, domain, true, out explanation);
			}
			finally
			{
				_dnsCache.Clear();
			}
		}

		private SpfQualifier CheckHostInternal(IPAddress ip, string sender, string domain, bool expandExplanation, out string explanation)
		{
			explanation = String.Empty;

			if (String.IsNullOrEmpty(domain))
			{
				return SpfQualifier.None;
			}

			if (String.IsNullOrEmpty(sender))
			{
				sender = "postmaster@unknown";
			}
			else if (!sender.Contains('@'))
			{
				sender = "postmaster@" + sender;
			}

			SpfQualifier result;
			T record;
			if (!TryLoadRecords(domain, out record, out result))
			{
				return result;
			}

			if ((record.Terms == null) || (record.Terms.Count == 0))
				return SpfQualifier.Neutral;

			if (record.Terms.OfType<SpfModifier>().GroupBy(m => m.Type).Where(g => (g.Key == SpfModifierType.Exp) || (g.Key == SpfModifierType.Redirect)).Any(g => g.Count() > 1))
				return SpfQualifier.PermError;

			#region Evaluate mechanism
			foreach (SpfMechanism mechanism in record.Terms.OfType<SpfMechanism>())
			{
				if (LookupCount > DnsLookupLimit)
					return SpfQualifier.PermError;

				SpfQualifier qualifier = CheckMechanism(mechanism, ip, sender, domain);

				if (qualifier != SpfQualifier.None)
				{
					result = qualifier;
					break;
				}
			}
			#endregion

			#region Evaluate modifiers
			if (result == SpfQualifier.None)
			{
				SpfModifier redirectModifier = record.Terms.OfType<SpfModifier>().FirstOrDefault(m => m.Type == SpfModifierType.Redirect);
				if (redirectModifier != null)
				{
					string redirectDomain = ExpandDomain(redirectModifier.Domain ?? String.Empty, ip, sender, domain);

					if (String.IsNullOrEmpty(redirectDomain) || (redirectDomain.Equals(domain, StringComparison.InvariantCultureIgnoreCase)))
					{
						result = SpfQualifier.PermError;
					}
					else
					{
						result = CheckHostInternal(ip, sender, redirectDomain, expandExplanation, out explanation);

						if (result == SpfQualifier.None)
							result = SpfQualifier.PermError;
					}
				}
			}
			else if ((result == SpfQualifier.Fail) && expandExplanation)
			{
				SpfModifier expModifier = record.Terms.OfType<SpfModifier>().Where(m => m.Type == SpfModifierType.Exp).FirstOrDefault();
				if (expModifier != null)
				{
					string target = ExpandDomain(expModifier.Domain, ip, sender, domain);

					if (String.IsNullOrEmpty(target))
					{
						explanation = String.Empty;
					}
					else
					{
						DnsMessage dnsMessage = ResolveDns(target, RecordType.Txt);
						if ((dnsMessage != null) && (dnsMessage.ReturnCode == ReturnCode.NoError))
						{
							TxtRecord txtRecord = dnsMessage.AnswerRecords.OfType<TxtRecord>().FirstOrDefault();
							if (txtRecord != null)
							{
								explanation = ExpandDomain(txtRecord.TextData, ip, sender, domain);
							}
						}
					}
				}
			}
			#endregion

			return (result != SpfQualifier.None) ? result : SpfQualifier.Neutral;
		}

		private SpfQualifier CheckMechanism(SpfMechanism mechanism, IPAddress ip, string sender, string domain)
		{
			DnsMessage dnsMessage;
			switch (mechanism.Type)
			{
				case SpfMechanismType.All:
					return mechanism.Qualifier;

				case SpfMechanismType.A:
					bool? isAMatch = IsIpMatch(String.IsNullOrEmpty(mechanism.Domain) ? domain : mechanism.Domain, ip, mechanism.Prefix, mechanism.Prefix6);
					if (!isAMatch.HasValue)
						return SpfQualifier.TempError;

					if (isAMatch.Value)
					{
						return mechanism.Qualifier;
					}
					break;

				case SpfMechanismType.Mx:
					dnsMessage = ResolveDns(ExpandDomain(String.IsNullOrEmpty(mechanism.Domain) ? domain : mechanism.Domain, ip, sender, domain), RecordType.Mx);
					if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
						return SpfQualifier.TempError;

					int mxCheckedCount = 0;

					foreach (MxRecord mxRecord in dnsMessage.AnswerRecords.OfType<MxRecord>())
					{
						if (++mxCheckedCount == 10)
							break;

						bool? isMxMatch = IsIpMatch(mxRecord.ExchangeDomainName, ip, mechanism.Prefix, mechanism.Prefix6);
						if (!isMxMatch.HasValue)
							return SpfQualifier.TempError;

						if (isMxMatch.Value)
						{
							return mechanism.Qualifier;
						}
					}
					break;

				case SpfMechanismType.Ip4:
				case SpfMechanismType.Ip6:
					IPAddress compareAddress;
					if (IPAddress.TryParse(mechanism.Domain, out compareAddress))
					{
						if (ip.AddressFamily != compareAddress.AddressFamily)
							return SpfQualifier.None;

						if (mechanism.Prefix.HasValue)
						{
							if ((mechanism.Prefix.Value < 0) || (mechanism.Prefix.Value > (compareAddress.AddressFamily == AddressFamily.InterNetworkV6 ? 128 : 32)))
								return SpfQualifier.PermError;

							if (ip.GetNetworkAddress(mechanism.Prefix.Value).Equals(compareAddress.GetNetworkAddress(mechanism.Prefix.Value)))
							{
								return mechanism.Qualifier;
							}
						}
						else if (ip.Equals(compareAddress))
						{
							return mechanism.Qualifier;
						}
					}
					else
					{
						return SpfQualifier.PermError;
					}

					break;

				case SpfMechanismType.Ptr:
					dnsMessage = ResolveDns(ip.GetReverseLookupAddress(), RecordType.Ptr);
					if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
						return SpfQualifier.TempError;

					string ptrCompareName = String.IsNullOrEmpty(mechanism.Domain) ? domain : mechanism.Domain;

					int ptrCheckedCount = 0;
					foreach (PtrRecord ptrRecord in dnsMessage.AnswerRecords.OfType<PtrRecord>())
					{
						if (++ptrCheckedCount == 10)
							break;

						bool? isPtrMatch = IsIpMatch(ptrRecord.PointerDomainName, ip, 0, 0);
						if (isPtrMatch.HasValue && isPtrMatch.Value)
						{
							if (ptrRecord.PointerDomainName.Equals(ptrCompareName, StringComparison.InvariantCultureIgnoreCase) || (ptrRecord.PointerDomainName.EndsWith("." + ptrCompareName, StringComparison.InvariantCultureIgnoreCase)))
								return mechanism.Qualifier;
						}
					}
					break;

				case SpfMechanismType.Exist:
					if (String.IsNullOrEmpty(mechanism.Domain))
						return SpfQualifier.PermError;

					dnsMessage = ResolveDns(ExpandDomain(mechanism.Domain, ip, sender, domain), RecordType.A);
					if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
						return SpfQualifier.TempError;

					if (dnsMessage.AnswerRecords.Count(record => (record.RecordType == RecordType.A)) > 0)
					{
						return mechanism.Qualifier;
					}
					break;

				case SpfMechanismType.Include:
					if (String.IsNullOrEmpty(mechanism.Domain) || (mechanism.Domain.Equals(domain, StringComparison.InvariantCultureIgnoreCase)))
						return SpfQualifier.PermError;

					string includeDomain = ExpandDomain(mechanism.Domain, ip, sender, domain);
					string explanation;
					switch (CheckHostInternal(ip, sender, includeDomain, false, out explanation))
					{
						case SpfQualifier.Pass:
							return mechanism.Qualifier;

						case SpfQualifier.Fail:
						case SpfQualifier.SoftFail:
						case SpfQualifier.Neutral:
							return SpfQualifier.None;

						case SpfQualifier.TempError:
							return SpfQualifier.TempError;

						case SpfQualifier.PermError:
						case SpfQualifier.None:
							return SpfQualifier.PermError;
					}
					break;

				default:
					return SpfQualifier.PermError;
			}

			return SpfQualifier.None;
		}

		private bool? IsIpMatch(string domain, IPAddress ipAddress, int? prefix4, int? prefix6)
		{
			int? prefix;
			RecordType recordType;
			if (ipAddress.AddressFamily == AddressFamily.InterNetworkV6)
			{
				prefix = prefix6;
				recordType = RecordType.Aaaa;
			}
			else
			{
				prefix = prefix4;
				recordType = RecordType.A;
			}

			if (prefix.HasValue)
			{
				ipAddress = ipAddress.GetNetworkAddress(prefix.Value);
			}

			DnsMessage dnsMessage = ResolveDns(domain, recordType);
			if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
				return null;

			foreach (var dnsRecord in dnsMessage.AnswerRecords.Where(record => record.RecordType == recordType).Cast<IAddressRecord>())
			{
				if (prefix.HasValue)
				{
					if (ipAddress.Equals(dnsRecord.Address.GetNetworkAddress(prefix.Value)))
						return true;
				}
				else
				{
					if (ipAddress.Equals(dnsRecord.Address))
						return true;
				}
			}

			return false;
		}

		protected DnsMessage ResolveDns(string domain, RecordType recordType)
		{
			string key = EnumHelper<RecordType>.ToString(recordType) + "|" + domain;

			DnsMessage result;
			if (!_dnsCache.TryGetValue(key, out result))
			{
				result = DnsClient.Default.Resolve(domain, recordType);
				_dnsCache[key] = result;
			}

			return result;
		}

		private string ExpandDomain(string pattern, IPAddress ip, string sender, string domain)
		{
			if (String.IsNullOrEmpty(pattern))
				return String.Empty;

			Regex regex = new Regex(@"(%%|%_|%-|%\{(?<letter>[slodiphcrtv])(?<count>\d*)(?<reverse>r?)(?<delimiter>[\.\-+,/=]*)})", RegexOptions.Compiled);

			return regex.Replace(pattern, p => ExpandMacro(p, ip, sender, domain));
		}

		private string ExpandMacro(Match pattern, IPAddress ip, string sender, string domain)
		{
			switch (pattern.Value)
			{
				case "%%":
					return "%";
				case "%_":
					return "_";
				case "%-":
					return "-";

				default:
					string letter;
					switch (pattern.Groups["letter"].Value)
					{
						case "s":
							letter = sender;
							break;
						case "l":
							// no boundary check needed, sender is validated on start of CheckHost
							letter = sender.Split('@')[0];
							break;
						case "o":
							// no boundary check needed, sender is validated on start of CheckHost
							letter = sender.Split('@')[1];
							break;
						case "d":
							letter = domain;
							break;
						case "i":
							letter = String.Join(".", ip.GetAddressBytes().Select(b => b.ToString()).ToArray());
							break;
						case "p":
							letter = "unknown";

							DnsMessage dnsMessage = ResolveDns(ip.GetReverseLookupAddress(), RecordType.Ptr);
							if ((dnsMessage == null) || ((dnsMessage.ReturnCode != ReturnCode.NoError) && (dnsMessage.ReturnCode != ReturnCode.NxDomain)))
							{
								break;
							}

							int ptrCheckedCount = 0;
							foreach (PtrRecord ptrRecord in dnsMessage.AnswerRecords.OfType<PtrRecord>())
							{
								if (++ptrCheckedCount == 10)
									break;

								bool? isPtrMatch = IsIpMatch(ptrRecord.PointerDomainName, ip, 0, 0);
								if (isPtrMatch.HasValue && isPtrMatch.Value)
								{
									if (letter == "unknown" || ptrRecord.PointerDomainName.EndsWith("." + domain, StringComparison.OrdinalIgnoreCase))
									{
										// use value, if first record or subdomain
										// but evaluate the other records
										letter = ptrRecord.PointerDomainName;
									}
									else if (ptrRecord.PointerDomainName.Equals(domain, StringComparison.OrdinalIgnoreCase))
									{
										// ptr equal domain --> best match, use it
										letter = ptrRecord.PointerDomainName;
										break;
									}
								}
							}
							break;
						case "v":
							letter = (ip.AddressFamily == AddressFamily.InterNetworkV6) ? "ip6" : "in-addr";
							break;
						case "h":
							letter = String.IsNullOrEmpty(HeloDomain) ? "unknown" : HeloDomain;
							break;
						case "c":
							IPAddress address =
								LocalIP
								?? NetworkInterface.GetAllNetworkInterfaces()
								                   .Where(n => (n.OperationalStatus == OperationalStatus.Up) && (n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
								                   .SelectMany(n => n.GetIPProperties().UnicastAddresses)
								                   .Select(u => u.Address)
								                   .FirstOrDefault(a => a.AddressFamily == ip.AddressFamily)
								?? ((ip.AddressFamily == AddressFamily.InterNetwork) ? IPAddress.Loopback : IPAddress.IPv6Loopback);
							letter = address.ToString();
							break;
						case "r":
							letter = String.IsNullOrEmpty(LocalDomain) ? System.Net.Dns.GetHostName() : LocalDomain;
							break;
						case "t":
							letter = ((int) (new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc) - DateTime.Now).TotalSeconds).ToString();
							break;
						default:
							return null;
					}

					// only letter
					if (pattern.Value.Length == 4)
						return letter;

					char[] delimiters = pattern.Groups["delimiter"].Value.ToCharArray();
					if (delimiters.Length == 0)
						delimiters = new[] { '.' };

					string[] parts = letter.Split(delimiters);

					if (pattern.Groups["reverse"].Value == "r")
						parts = parts.Reverse().ToArray();

					int count = Int32.MaxValue;
					if (!String.IsNullOrEmpty(pattern.Groups["count"].Value))
					{
						count = Int32.Parse(pattern.Groups["count"].Value);
					}

					if (count < 1)
						return null;

					count = Math.Min(count, parts.Length);

					return String.Join(".", parts, (parts.Length - count), count);
			}
		}
	}
}