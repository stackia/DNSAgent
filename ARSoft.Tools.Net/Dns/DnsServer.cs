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
using System.Diagnostics;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using ARSoft.Tools.Net.Socket;

namespace ARSoft.Tools.Net.Dns
{
	/// <summary>
	///   Provides a base dns server interface
	/// </summary>
	public class DnsServer : IDisposable
	{
		private class MyState
		{
			public IAsyncResult AsyncResult;
			public TcpClient Client;
			public NetworkStream Stream;
			public DnsMessageBase Response;
			public byte[] NextTsigMac;
			public byte[] Buffer;
			public int BytesToReceive;
			public Timer Timer;

			private long _timeOutUtcTicks;

			public long TimeRemaining
			{
				get
				{
					long res = (_timeOutUtcTicks - DateTime.UtcNow.Ticks) / TimeSpan.TicksPerMillisecond;
					return res > 0 ? res : 0;
				}
				set { _timeOutUtcTicks = DateTime.UtcNow.Ticks + value * TimeSpan.TicksPerMillisecond; }
			}
		}

		/// <summary>
		///   Represents the method, that will be called to get the response for a specific dns query
		/// </summary>
		/// <param name="query"> The query, for that a response should be returned </param>
		/// <param name="clientAddress"> The ip address from which the queries comes </param>
		/// <param name="protocolType"> The protocol which was used for the query </param>
		/// <returns> A DnsMessage with the response to the query </returns>
		public delegate DnsMessageBase ProcessQuery(DnsMessageBase query, IPAddress clientAddress, ProtocolType protocolType);

		/// <summary>
		///   Represents the method, that will be called to get the keydata for processing a tsig signed message
		/// </summary>
		/// <param name="algorithm"> The algorithm which is used in the message </param>
		/// <param name="keyName"> The keyname which is used in the message </param>
		/// <returns> Binary representation of the key </returns>
		public delegate byte[] SelectTsigKey(TSigAlgorithm algorithm, string keyName);

		private const int _DNS_PORT = 53;

		private TcpListener _tcpListener;
		private UdpListener _udpListener;
		private readonly IPEndPoint _bindEndPoint;

		private readonly int _udpListenerCount;
		private readonly int _tcpListenerCount;

		private int _availableUdpListener;
		private bool _hasActiveUdpListener;

		private int _availableTcpListener;
		private bool _hasActiveTcpListener;

		private readonly ProcessQuery _processQueryDelegate;

		/// <summary>
		///   Method that will be called to get the keydata for processing a tsig signed message
		/// </summary>
		public SelectTsigKey TsigKeySelector;

		/// <summary>
		///   Gets or sets the timeout for sending and receiving data
		/// </summary>
		public int Timeout { get; set; }

		/// <summary>
		///   Creates a new dns server instance which will listen on all available interfaces
		/// </summary>
		/// <param name="udpListenerCount"> The count of threads listings on udp, 0 to deactivate udp </param>
		/// <param name="tcpListenerCount"> The count of threads listings on tcp, 0 to deactivate tcp </param>
		/// <param name="processQuery"> Method, which process the queries and returns the response </param>
		public DnsServer(int udpListenerCount, int tcpListenerCount, ProcessQuery processQuery)
			: this(IPAddress.Any, udpListenerCount, tcpListenerCount, processQuery) {}

		/// <summary>
		///   Creates a new dns server instance
		/// </summary>
		/// <param name="bindAddress"> The address, on which should be listend </param>
		/// <param name="udpListenerCount"> The count of threads listings on udp, 0 to deactivate udp </param>
		/// <param name="tcpListenerCount"> The count of threads listings on tcp, 0 to deactivate tcp </param>
		/// <param name="processQuery"> Method, which process the queries and returns the response </param>
		public DnsServer(IPAddress bindAddress, int udpListenerCount, int tcpListenerCount, ProcessQuery processQuery)
			: this(new IPEndPoint(bindAddress, _DNS_PORT), udpListenerCount, tcpListenerCount, processQuery) {}

		/// <summary>
		///   Creates a new dns server instance
		/// </summary>
		/// <param name="bindEndPoint"> The endpoint, on which should be listend </param>
		/// <param name="udpListenerCount"> The count of threads listings on udp, 0 to deactivate udp </param>
		/// <param name="tcpListenerCount"> The count of threads listings on tcp, 0 to deactivate tcp </param>
		/// <param name="processQuery"> Method, which process the queries and returns the response </param>
		public DnsServer(IPEndPoint bindEndPoint, int udpListenerCount, int tcpListenerCount, ProcessQuery processQuery)
		{
			_bindEndPoint = bindEndPoint;
			_processQueryDelegate = processQuery;

			_udpListenerCount = udpListenerCount;
			_tcpListenerCount = tcpListenerCount;

			Timeout = 120000;
		}

		/// <summary>
		///   Starts the server
		/// </summary>
		public void Start()
		{
			if (_udpListenerCount > 0)
			{
				_availableUdpListener = _udpListenerCount;
				_udpListener = new UdpListener(_bindEndPoint);
				StartUdpListen();
			}

			if (_tcpListenerCount > 0)
			{
				_availableTcpListener = _tcpListenerCount;
				_tcpListener = new TcpListener(_bindEndPoint);
				_tcpListener.Start();
				StartTcpAcceptConnection();
			}
		}

		/// <summary>
		///   Stops the server
		/// </summary>
		public void Stop()
		{
			if (_udpListenerCount > 0)
			{
				_udpListener.Dispose();
			}
			if (_tcpListenerCount > 0)
			{
				_tcpListener.Stop();
			}
		}

		private void StartUdpListen()
		{
			try
			{
				lock (_udpListener)
				{
					if ((_availableUdpListener > 0) && !_hasActiveUdpListener)
					{
						_availableUdpListener--;
						_hasActiveUdpListener = true;
						_udpListener.BeginReceive(EndUdpReceive, null);
					}
				}
			}
			catch (Exception e)
			{
				lock (_udpListener)
				{
					_hasActiveUdpListener = false;
				}
				HandleUdpException(e);
			}
		}

		private void EndUdpReceive(IAsyncResult ar)
		{
			try
			{
				lock (_udpListener)
				{
					_hasActiveUdpListener = false;
				}
				StartUdpListen();

				IPEndPoint endpoint;

				byte[] buffer = _udpListener.EndReceive(ar, out endpoint);

				DnsMessageBase query;
				byte[] originalMac;
				try
				{
					query = DnsMessageBase.CreateByFlag(buffer, TsigKeySelector, null);
					originalMac = (query.TSigOptions == null) ? null : query.TSigOptions.Mac;
				}
				catch (Exception e)
				{
					throw new Exception("Error parsing dns query", e);
				}

				DnsMessageBase response;
				try
				{
					response = ProcessMessage(query, endpoint.Address, ProtocolType.Udp);
				}
				catch (Exception ex)
				{
					OnExceptionThrown(ex);
					response = null;
				}

				if (response == null)
				{
					response = query;
					query.IsQuery = false;
					query.ReturnCode = ReturnCode.ServerFailure;
				}

				int length = response.Encode(false, originalMac, out buffer);

				#region Truncating
				DnsMessage message = response as DnsMessage;

				if (message != null)
				{
					int maxLength = 512;
					if (query.IsEDnsEnabled && message.IsEDnsEnabled)
					{
						maxLength = Math.Max(512, (int) message.EDnsOptions.UdpPayloadSize);
					}

					while (length > maxLength)
					{
						// First step: remove data from additional records except the opt record
						if ((message.IsEDnsEnabled && (message.AdditionalRecords.Count > 1)) || (!message.IsEDnsEnabled && (message.AdditionalRecords.Count > 0)))
						{
							for (int i = message.AdditionalRecords.Count - 1; i >= 0; i--)
							{
								if (message.AdditionalRecords[i].RecordType != RecordType.Opt)
								{
									message.AdditionalRecords.RemoveAt(i);
								}
							}

							length = message.Encode(false, originalMac, out buffer);
							continue;
						}

						int savedLength = 0;
						if (message.AuthorityRecords.Count > 0)
						{
							for (int i = message.AuthorityRecords.Count - 1; i >= 0; i--)
							{
								savedLength += message.AuthorityRecords[i].MaximumLength;
								message.AuthorityRecords.RemoveAt(i);

								if ((length - savedLength) < maxLength)
								{
									break;
								}
							}

							message.IsTruncated = true;

							length = message.Encode(false, originalMac, out buffer);
							continue;
						}

						if (message.AnswerRecords.Count > 0)
						{
							for (int i = message.AnswerRecords.Count - 1; i >= 0; i--)
							{
								savedLength += message.AnswerRecords[i].MaximumLength;
								message.AnswerRecords.RemoveAt(i);

								if ((length - savedLength) < maxLength)
								{
									break;
								}
							}

							message.IsTruncated = true;

							length = message.Encode(false, originalMac, out buffer);
							continue;
						}

						if (message.Questions.Count > 0)
						{
							for (int i = message.Questions.Count - 1; i >= 0; i--)
							{
								savedLength += message.Questions[i].MaximumLength;
								message.Questions.RemoveAt(i);

								if ((length - savedLength) < maxLength)
								{
									break;
								}
							}

							message.IsTruncated = true;

							length = message.Encode(false, originalMac, out buffer);
						}
					}
				}
				#endregion

				_udpListener.BeginSend(buffer, 0, length, endpoint, EndUdpSend, null);
			}
			catch (Exception e)
			{
				HandleUdpException(e);
			}
		}

		private DnsMessageBase ProcessMessage(DnsMessageBase query, IPAddress ipAddress, ProtocolType protocolType)
		{
			if (query.TSigOptions != null)
			{
				switch (query.TSigOptions.ValidationResult)
				{
					case ReturnCode.BadKey:
					case ReturnCode.BadSig:
						query.IsQuery = false;
						query.ReturnCode = ReturnCode.NotAuthoritive;
						query.TSigOptions.Error = query.TSigOptions.ValidationResult;
						query.TSigOptions.KeyData = null;

						if (InvalidSignedMessageReceived != null)
							InvalidSignedMessageReceived(this, new InvalidSignedMessageEventArgs(query));

						return query;

					case ReturnCode.BadTime:
						query.IsQuery = false;
						query.ReturnCode = ReturnCode.NotAuthoritive;
						query.TSigOptions.Error = query.TSigOptions.ValidationResult;
						query.TSigOptions.OtherData = new byte[6];
						int tmp = 0;
						TSigRecord.EncodeDateTime(query.TSigOptions.OtherData, ref tmp, DateTime.Now);

						if (InvalidSignedMessageReceived != null)
							InvalidSignedMessageReceived(this, new InvalidSignedMessageEventArgs(query));

						return query;
				}
			}

			return _processQueryDelegate(query, ipAddress, protocolType);
		}

		private void EndUdpSend(IAsyncResult ar)
		{
			try
			{
				_udpListener.EndSend(ar);
			}
			catch (Exception e)
			{
				HandleUdpException(e);
			}

			lock (_udpListener)
			{
				_availableUdpListener++;
			}
			StartUdpListen();
		}

		private void StartTcpAcceptConnection()
		{
			try
			{
				lock (_tcpListener)
				{
					if ((_availableTcpListener > 0) && !_hasActiveTcpListener)
					{
						_availableTcpListener--;
						_hasActiveTcpListener = true;
						_tcpListener.BeginAcceptTcpClient(EndTcpAcceptConnection, null);
					}
				}
			}
			catch (Exception e)
			{
				lock (_tcpListener)
				{
					_hasActiveTcpListener = false;
				}
				HandleTcpException(e, null, null);
			}
		}

		private void EndTcpAcceptConnection(IAsyncResult ar)
		{
			TcpClient client = null;
			NetworkStream stream = null;

			try
			{
				client = _tcpListener.EndAcceptTcpClient(ar);
				lock (_tcpListener)
				{
					_hasActiveTcpListener = false;
					StartTcpAcceptConnection();
				}

				stream = client.GetStream();

				MyState state =
					new MyState
					{
						Client = client,
						Stream = stream,
						Buffer = new byte[2],
						BytesToReceive = 2,
						TimeRemaining = Timeout
					};

				state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
				state.AsyncResult = stream.BeginRead(state.Buffer, 0, 2, EndTcpReadLength, state);
			}
			catch (Exception e)
			{
				HandleTcpException(e, stream, client);
			}
		}

		private void TcpTimedOut(object timeoutState)
		{
			MyState state = timeoutState as MyState;

			if ((state != null) && (state.AsyncResult != null) && !state.AsyncResult.IsCompleted)
			{
				try
				{
					if (state.Stream != null)
					{
						state.Stream.Close();
					}
				}
				catch {}

				try
				{
					if (state.Client != null)
					{
						state.Client.Close();
					}
				}
				catch {}
			}
		}


		private void EndTcpReadLength(IAsyncResult ar)
		{
			TcpClient client = null;
			NetworkStream stream = null;

			try
			{
				MyState state = (MyState) ar.AsyncState;
				client = state.Client;
				stream = state.Stream;

				state.Timer.Dispose();

				state.BytesToReceive -= stream.EndRead(ar);

				if (state.BytesToReceive > 0)
				{
					if (!IsTcpClientConnected(client))
					{
						HandleTcpException(null, stream, client);
						return;
					}

					state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
					state.AsyncResult = stream.BeginRead(state.Buffer, state.Buffer.Length - state.BytesToReceive, state.BytesToReceive, EndTcpReadLength, state);
				}
				else
				{
					int tmp = 0;
					int length = DnsMessageBase.ParseUShort(state.Buffer, ref tmp);

					if (length > 0)
					{
						state.Buffer = new byte[length];

						state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
						state.AsyncResult = stream.BeginRead(state.Buffer, 0, length, EndTcpReadData, state);
					}
					else
					{
						HandleTcpException(null, stream, client);
					}
				}
			}
			catch (Exception e)
			{
				HandleTcpException(e, stream, client);
			}
		}

		private static bool IsTcpClientConnected(TcpClient client)
		{
			if (!client.Connected)
				return false;

			if (client.Client.Poll(0, SelectMode.SelectRead))
			{
				if (client.Connected)
				{
					byte[] b = new byte[1];
					try
					{
						if (client.Client.Receive(b, SocketFlags.Peek) == 0)
						{
							return false;
						}
					}
					catch
					{
						return false;
					}
				}
			}

			return true;
		}

		private void EndTcpReadData(IAsyncResult ar)
		{
			TcpClient client = null;
			NetworkStream stream = null;

			try
			{
				MyState state = (MyState) ar.AsyncState;
				client = state.Client;
				stream = state.Stream;

				state.Timer.Dispose();

				state.BytesToReceive -= stream.EndRead(ar);

				if (state.BytesToReceive > 0)
				{
					if (!IsTcpClientConnected(client))
					{
						HandleTcpException(null, stream, client);
						return;
					}

					state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
					state.AsyncResult = stream.BeginRead(state.Buffer, state.Buffer.Length - state.BytesToReceive, state.BytesToReceive, EndTcpReadData, state);
				}
				else
				{
					DnsMessageBase query;
					try
					{
						query = DnsMessageBase.CreateByFlag(state.Buffer, TsigKeySelector, null);
						state.NextTsigMac = (query.TSigOptions == null) ? null : query.TSigOptions.Mac;
					}
					catch (Exception e)
					{
						throw new Exception("Error parsing dns query", e);
					}

					try
					{
						state.Response = ProcessMessage(query, ((IPEndPoint) client.Client.RemoteEndPoint).Address, ProtocolType.Tcp);
					}
					catch (Exception ex)
					{
						OnExceptionThrown(ex);
						state.Response = null;
					}

					ProcessAndSendTcpResponse(state, false);
				}
			}
			catch (Exception e)
			{
				HandleTcpException(e, stream, client);
			}
		}

		private void ProcessAndSendTcpResponse(MyState state, bool isSubSequentResponse)
		{
			if (state.Response == null)
			{
				state.Response = DnsMessageBase.CreateByFlag(state.Buffer, TsigKeySelector, null);
				state.Response.IsQuery = false;
				state.Response.AdditionalRecords.Clear();
				state.Response.AuthorityRecords.Clear();
				state.Response.ReturnCode = ReturnCode.ServerFailure;
			}

			byte[] newTsigMac;

			int length = state.Response.Encode(true, state.NextTsigMac, isSubSequentResponse, out state.Buffer, out newTsigMac);

			if (length > 65535)
			{
				if ((state.Response.Questions.Count == 0) || (state.Response.Questions[0].RecordType != RecordType.Axfr))
				{
					OnExceptionThrown(new ArgumentException("The length of the serialized response is greater than 65,535 bytes"));
					state.Response = DnsMessageBase.CreateByFlag(state.Buffer, TsigKeySelector, null);
					state.Response.IsQuery = false;
					state.Response.ReturnCode = ReturnCode.ServerFailure;
					state.Response.AdditionalRecords.Clear();
					state.Response.AuthorityRecords.Clear();
					length = state.Response.Encode(true, state.NextTsigMac, isSubSequentResponse, out state.Buffer, out newTsigMac);
				}
				else
				{
					List<DnsRecordBase> nextPacketRecords = new List<DnsRecordBase>();

					do
					{
						int lastIndex = Math.Min(500, state.Response.AnswerRecords.Count / 2);
						int removeCount = state.Response.AnswerRecords.Count - lastIndex;

						nextPacketRecords.InsertRange(0, state.Response.AnswerRecords.GetRange(lastIndex, removeCount));
						state.Response.AnswerRecords.RemoveRange(lastIndex, removeCount);

						length = state.Response.Encode(true, state.NextTsigMac, isSubSequentResponse, out state.Buffer, out newTsigMac);
					} while (length > 65535);

					state.Response.AnswerRecords = nextPacketRecords;
				}
			}
			else
			{
				state.Response = null;
			}

			state.NextTsigMac = newTsigMac;

			state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
			state.AsyncResult = state.Stream.BeginWrite(state.Buffer, 0, length, EndTcpSendData, state);
		}

		private void EndTcpSendData(IAsyncResult ar)
		{
			TcpClient client = null;
			NetworkStream stream = null;

			try
			{
				MyState state = (MyState) ar.AsyncState;
				client = state.Client;
				stream = state.Stream;

				state.Timer.Dispose();

				stream.EndWrite(ar);

				if (state.Response == null)
				{
					if (state.NextTsigMac == null)
					{
						state.Buffer = new byte[2];
						state.BytesToReceive = 2;
						state.TimeRemaining = Timeout;

						state.Timer = new Timer(TcpTimedOut, state, state.TimeRemaining, System.Threading.Timeout.Infinite);
						state.AsyncResult = stream.BeginRead(state.Buffer, 0, 2, EndTcpReadLength, state);
					}
					else
					{
						// Since support for multiple tsig signed messages is not finished, just close connection after response to first signed query
						state.Stream.Close();
						state.Client.Close();
					}
				}
				else
				{
					ProcessAndSendTcpResponse(state, true);
				}
			}
			catch (Exception e)
			{
				HandleTcpException(e, stream, client);
			}
		}

		private void HandleUdpException(Exception e)
		{
			lock (_udpListener)
			{
				_availableUdpListener++;
			}
			StartUdpListen();

			OnExceptionThrown(e);
		}

		private void HandleTcpException(Exception e, NetworkStream stream, TcpClient client)
		{
			try
			{
				if (stream != null)
				{
					stream.Close();
				}
			}
			catch {}

			try
			{
				if (client != null)
				{
					client.Close();
				}
			}
			catch {}

			lock (_tcpListener)
			{
				_availableTcpListener++;
			}
			StartTcpAcceptConnection();

			if (e != null)
				OnExceptionThrown(e);
		}

		private void OnExceptionThrown(Exception e)
		{
			if (e is ObjectDisposedException)
				return;

			if (ExceptionThrown != null)
			{
				ExceptionThrown(this, new ExceptionEventArgs(e));
			}
			else
			{
				Trace.TraceError(e.ToString());
			}
		}

		/// <summary>
		///   This event is fired on exceptions of the listeners. You can use it for custom logging.
		/// </summary>
		public event EventHandler<ExceptionEventArgs> ExceptionThrown;

		/// <summary>
		///   This event is fired whenever a message is received, that is not correct signed
		/// </summary>
		public event EventHandler<InvalidSignedMessageEventArgs> InvalidSignedMessageReceived;

		void IDisposable.Dispose()
		{
			Stop();
		}
	}
}