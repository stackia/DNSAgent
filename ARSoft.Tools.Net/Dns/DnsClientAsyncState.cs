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
using System.Net.Sockets;
using System.Text;
using System.Threading;

namespace ARSoft.Tools.Net.Dns
{
	internal class DnsClientAsyncState<TMessage> : IAsyncResult
		where TMessage : DnsMessageBase
	{
		internal List<DnsClientEndpointInfo> EndpointInfos;
		internal int EndpointInfoIndex;

		internal TMessage Query;
		internal byte[] QueryData;
		internal int QueryLength;

		internal DnsServer.SelectTsigKey TSigKeySelector;
		internal byte[] TSigOriginalMac;

		internal TMessage PartialMessage;
		internal List<TMessage> Responses;

		internal Timer Timer;
		internal bool TimedOut;

		private long _timeOutUtcTicks;

		internal long TimeRemaining
		{
			get
			{
				long res = (_timeOutUtcTicks - DateTime.UtcNow.Ticks) / TimeSpan.TicksPerMillisecond;
				return res > 0 ? res : 0;
			}
			set { _timeOutUtcTicks = DateTime.UtcNow.Ticks + value * TimeSpan.TicksPerMillisecond; }
		}

		internal System.Net.Sockets.Socket UdpClient;
		internal EndPoint UdpEndpoint;

		internal byte[] Buffer;

		internal TcpClient TcpClient;
		internal NetworkStream TcpStream;
		internal int TcpBytesToReceive;

		internal AsyncCallback UserCallback;
		public object AsyncState { get; internal set; }
		public bool IsCompleted { get; private set; }

		public bool CompletedSynchronously
		{
			get { return false; }
		}

		private ManualResetEvent _waitHandle;

		public WaitHandle AsyncWaitHandle
		{
			get { return _waitHandle ?? (_waitHandle = new ManualResetEvent(IsCompleted)); }
		}

		internal void SetCompleted()
		{
			QueryData = null;

			if (Timer != null)
			{
				Timer.Dispose();
				Timer = null;
			}

			IsCompleted = true;
			if (_waitHandle != null)
				_waitHandle.Set();

			if (UserCallback != null)
				UserCallback(this);
		}

		public DnsClientAsyncState<TMessage> CreateTcpCloneWithoutCallback()
		{
			return
				new DnsClientAsyncState<TMessage>
				{
					EndpointInfos = EndpointInfos,
					EndpointInfoIndex = EndpointInfoIndex,
					Query = Query,
					QueryData = QueryData,
					QueryLength = QueryLength,
					TSigKeySelector = TSigKeySelector,
					TSigOriginalMac = TSigOriginalMac,
					Responses = Responses,
					_timeOutUtcTicks = _timeOutUtcTicks
				};
		}
	}
}