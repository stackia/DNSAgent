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

namespace ARSoft.Tools.Net.Dns.DynamicUpdate
{
	/// <summary>
	///   <para>Dynamic DNS update message</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc2136">RFC 2136</see>
	///   </para>
	/// </summary>
	public class DnsUpdateMessage : DnsMessageBase
	{
		/// <summary>
		///   Parses a the contents of a byte array as DnsUpdateMessage
		/// </summary>
		/// <param name="data">Buffer, that contains the message data</param>
		/// <returns>A new instance of the DnsUpdateMessage class</returns>
		public static DnsUpdateMessage Parse(byte[] data)
		{
			return Parse<DnsUpdateMessage>(data);
		}

		/// <summary>
		///   Creates a new instance of the DnsUpdateMessage class
		/// </summary>
		public DnsUpdateMessage()
		{
			OperationCode = OperationCode.Update;
		}

		private List<PrequisiteBase> _prequisites;
		private List<UpdateBase> _updates;

		/// <summary>
		///   Gets or sets the zone name
		/// </summary>
		public string ZoneName
		{
			get { return Questions.Count > 0 ? Questions[0].Name : null; }
			set { Questions = new List<DnsQuestion>() { new DnsQuestion(value, RecordType.Soa, RecordClass.Any) }; }
		}

		/// <summary>
		///   Gets or sets the entries in the prerequisites section
		/// </summary>
		public List<PrequisiteBase> Prequisites
		{
			get { return _prequisites ?? (_prequisites = new List<PrequisiteBase>()); }
			set { _prequisites = value; }
		}

		/// <summary>
		///   Gets or sets the entries in the update section
		/// </summary>
		public List<UpdateBase> Updates
		{
			get { return _updates ?? (_updates = new List<UpdateBase>()); }
			set { _updates = value; }
		}

		internal override bool IsTcpUsingRequested
		{
			get { return false; }
		}

		internal override bool IsTcpResendingRequested
		{
			get { return false; }
		}

		internal override bool IsTcpNextMessageWaiting(bool isSubsequentResponseMessage)
		{
			return false;
		}

		protected override void PrepareEncoding()
		{
			AnswerRecords = (Prequisites != null ? Prequisites.Cast<DnsRecordBase>().ToList() : new List<DnsRecordBase>());
			AuthorityRecords = (Updates != null ? Updates.Cast<DnsRecordBase>().ToList() : new List<DnsRecordBase>());
		}

		protected override void FinishParsing()
		{
			Prequisites =
				AnswerRecords.ConvertAll<PrequisiteBase>(
					record =>
					{
						if ((record.RecordClass == RecordClass.Any) && (record.RecordDataLength == 0))
						{
							return new RecordExistsPrequisite(record.Name, record.RecordType);
						}
						else if (record.RecordClass == RecordClass.Any)
						{
							return new RecordExistsPrequisite(record);
						}
						else if ((record.RecordClass == RecordClass.None) && (record.RecordDataLength == 0))
						{
							return new RecordNotExistsPrequisite(record.Name, record.RecordType);
						}
						else if ((record.RecordClass == RecordClass.Any) && (record.RecordType == RecordType.Any))
						{
							return new NameIsInUsePrequisite(record.Name);
						}
						else if ((record.RecordClass == RecordClass.None) && (record.RecordType == RecordType.Any))
						{
							return new NameIsNotInUsePrequisite(record.Name);
						}
						else
						{
							return null;
						}
					}).Where(prequisite => (prequisite != null)).ToList();

			Updates =
				AuthorityRecords.ConvertAll<UpdateBase>(
					record =>
					{
						if (record.TimeToLive != 0)
						{
							return new AddRecordUpdate(record);
						}
						else if ((record.RecordType == RecordType.Any) && (record.RecordClass == RecordClass.Any) && (record.RecordDataLength == 0))
						{
							return new DeleteAllRecordsUpdate(record.Name);
						}
						else if ((record.RecordClass == RecordClass.Any) && (record.RecordDataLength == 0))
						{
							return new DeleteRecordUpdate(record.Name, record.RecordType);
						}
						else if (record.RecordClass == RecordClass.None)
						{
							return new DeleteRecordUpdate(record);
						}
						else
						{
							return null;
						}
					}).Where(update => (update != null)).ToList();
		}
	}
}