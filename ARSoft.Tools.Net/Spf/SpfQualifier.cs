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
	///   Qualifier of spf mechanism
	/// </summary>
	public enum SpfQualifier
	{
		/// <summary>
		///   No records were published or no checkable sender could be determined
		/// </summary>
		None,

		/// <summary>
		///   Client is allowed to send mail with the given identity
		/// </summary>
		Pass,

		/// <summary>
		///   Client is explicit not allowed to send mail with the given identity
		/// </summary>
		Fail,

		/// <summary>
		///   Client is not allowed to send mail with the given identity
		/// </summary>
		SoftFail,

		/// <summary>
		///   No statement if a client is allowed or not allowed to send mail with the given identity
		/// </summary>
		Neutral,

		/// <summary>
		///   A transient error encountered while performing the check
		/// </summary>
		TempError,

		/// <summary>
		///   The published record could not be correctly interpreted
		/// </summary>
		PermError,
	}
}