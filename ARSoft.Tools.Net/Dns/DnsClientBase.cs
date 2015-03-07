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
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Threading;

namespace ARSoft.Tools.Net.Dns
{
	public abstract class DnsClientBase
	{
		private readonly List<IPAddress> _servers;
		private readonly bool _isAnyServerMulticast;
		private readonly int _port;

		internal DnsClientBase(List<IPAddress> servers, int queryTimeout, int port)
		{
			_servers = servers.OrderBy(s => s.AddressFamily == AddressFamily.InterNetworkV6 ? 0 : 1).ToList();
			_isAnyServerMulticast = servers.Any(s => s.IsMulticast());
			QueryTimeout = queryTimeout;
			_port = port;
		}

		/// <summary>
		///   Milliseconds after which a query times out.
		/// </summary>
		public int QueryTimeout { get; private set; }

		/// <summary>
		///   Gets or set a value indicating whether the response is validated as described in
		///   <see
		///     cref="!:http://tools.ietf.org/id/draft-vixie-dnsext-dns0x20-00.txt">
		///     draft-vixie-dnsext-dns0x20-00
		///   </see>
		/// </summary>
		public bool IsResponseValidationEnabled { get; set; }

		/// <summary>
		///   Gets or set a value indicating whether the query labels are used for additional validation as described in
		///   <see
		///     cref="!:http://tools.ietf.org/id/draft-vixie-dnsext-dns0x20-00.txt">
		///     draft-vixie-dnsext-dns0x20-00
		///   </see>
		/// </summary>
		public bool Is0x20ValidationEnabled { get; set; }

		protected abstract int MaximumQueryMessageSize { get; }

		protected abstract bool AreMultipleResponsesAllowedInParallelMode { get; }

		protected TMessage SendMessage<TMessage>(TMessage message)
			where TMessage : DnsMessageBase, new()
		{
			int messageLength;
			byte[] messageData;
			DnsServer.SelectTsigKey tsigKeySelector;
			byte[] tsigOriginalMac;

			PrepareMessage(message, out messageLength, out messageData, out tsigKeySelector, out tsigOriginalMac);

			bool sendByTcp = ((messageLength > MaximumQueryMessageSize) || message.IsTcpUsingRequested);

			var endpointInfos = GetEndpointInfos<TMessage>();

			for (int i = 0; i < endpointInfos.Count; i++)
			{
				TcpClient tcpClient = null;
				NetworkStream tcpStream = null;

				try
				{
					var endpointInfo = endpointInfos[i];

					IPAddress responderAddress;
					byte[] resultData = sendByTcp ? QueryByTcp(endpointInfo.ServerAddress, messageData, messageLength, ref tcpClient, ref tcpStream, out responderAddress) : QueryByUdp(endpointInfo, messageData, messageLength, out responderAddress);

					if (resultData != null)
					{
						TMessage result;

						try
						{
							result = DnsMessageBase.Parse<TMessage>(resultData, tsigKeySelector, tsigOriginalMac);
						}
						catch (Exception e)
						{
							Trace.TraceError("Error on dns query: " + e);
							continue;
						}

						if (!ValidateResponse(message, result))
							continue;

						if ((result.ReturnCode == ReturnCode.ServerFailure) && (i != endpointInfos.Count - 1))
						{
							continue;
						}

						if (result.IsTcpResendingRequested)
						{
							resultData = QueryByTcp(responderAddress, messageData, messageLength, ref tcpClient, ref tcpStream, out responderAddress);
							if (resultData != null)
							{
								TMessage tcpResult;

								try
								{
									tcpResult = DnsMessageBase.Parse<TMessage>(resultData, tsigKeySelector, tsigOriginalMac);
								}
								catch (Exception e)
								{
									Trace.TraceError("Error on dns query: " + e);
									continue;
								}

								if (tcpResult.ReturnCode == ReturnCode.ServerFailure)
								{
									if (i != endpointInfos.Count - 1)
									{
										continue;
									}
								}
								else
								{
									result = tcpResult;
								}
							}
						}

						bool isTcpNextMessageWaiting = result.IsTcpNextMessageWaiting(false);
						bool isSucessfullFinished = true;

						while (isTcpNextMessageWaiting)
						{
							resultData = QueryByTcp(responderAddress, null, 0, ref tcpClient, ref tcpStream, out responderAddress);
							if (resultData != null)
							{
								TMessage tcpResult;

								try
								{
									tcpResult = DnsMessageBase.Parse<TMessage>(resultData, tsigKeySelector, tsigOriginalMac);
								}
								catch (Exception e)
								{
									Trace.TraceError("Error on dns query: " + e);
									isSucessfullFinished = false;
									break;
								}

								if (tcpResult.ReturnCode == ReturnCode.ServerFailure)
								{
									isSucessfullFinished = false;
									break;
								}
								else
								{
									result.AnswerRecords.AddRange(tcpResult.AnswerRecords);
									isTcpNextMessageWaiting = tcpResult.IsTcpNextMessageWaiting(true);
								}
							}
							else
							{
								isSucessfullFinished = false;
								break;
							}
						}

						if (isSucessfullFinished)
							return result;
					}
				}
				finally
				{
					try
					{
						if (tcpStream != null)
							tcpStream.Dispose();
						if (tcpClient != null)
							tcpClient.Close();
					}
					catch {}
				}
			}

			return null;
		}

		protected List<TMessage> SendMessageParallel<TMessage>(TMessage message)
			where TMessage : DnsMessageBase, new()
		{
			IAsyncResult ar = BeginSendMessageParallel(message, null, null);
			ar.AsyncWaitHandle.WaitOne();
			return EndSendMessageParallel<TMessage>(ar);
		}

		private bool ValidateResponse<TMessage>(TMessage message, TMessage result)
			where TMessage : DnsMessageBase
		{
			if (IsResponseValidationEnabled)
			{
				if ((result.ReturnCode == ReturnCode.NoError) || (result.ReturnCode == ReturnCode.NxDomain))
				{
					if (message.TransactionID != result.TransactionID)
						return false;

					if ((message.Questions == null) || (result.Questions == null))
						return false;

					if ((message.Questions.Count != result.Questions.Count))
						return false;

					for (int j = 0; j < message.Questions.Count; j++)
					{
						DnsQuestion queryQuestion = message.Questions[j];
						DnsQuestion responseQuestion = message.Questions[j];

						if ((queryQuestion.RecordClass != responseQuestion.RecordClass)
						    || (queryQuestion.RecordType != responseQuestion.RecordType)
						    || (queryQuestion.Name != responseQuestion.Name))
						{
							return false;
						}
					}
				}
			}

			return true;
		}

		private void PrepareMessage<TMessage>(TMessage message, out int messageLength, out byte[] messageData, out DnsServer.SelectTsigKey tsigKeySelector, out byte[] tsigOriginalMac)
			where TMessage : DnsMessageBase, new()
		{
			if (message.TransactionID == 0)
			{
				message.TransactionID = (ushort) new Random().Next(0xffff);
			}

			if (Is0x20ValidationEnabled)
			{
				message.Questions.ForEach(q => q.Name = Add0x20Bits(q.Name));
			}

			messageLength = message.Encode(false, out messageData);

			if (message.TSigOptions != null)
			{
				tsigKeySelector = (n, a) => message.TSigOptions.KeyData;
				tsigOriginalMac = message.TSigOptions.Mac;
			}
			else
			{
				tsigKeySelector = null;
				tsigOriginalMac = null;
			}
		}

		private static string Add0x20Bits(string name)
		{
			char[] res = new char[name.Length];

			Random random = new Random();

			for (int i = 0; i < name.Length; i++)
			{
				bool isLower = random.Next(0, 1000) > 500;

				char current = name[i];

				if (!isLower && current >= 'A' && current <= 'Z')
				{
					current = (char) (current + 0x20);
				}
				else if (isLower && current >= 'a' && current <= 'z')
				{
					current = (char) (current - 0x20);
				}

				res[i] = current;
			}

			return new string(res);
		}

		private byte[] QueryByUdp(DnsClientEndpointInfo endpointInfo, byte[] messageData, int messageLength, out IPAddress responderAddress)
		{
			using (System.Net.Sockets.Socket udpClient = new System.Net.Sockets.Socket(endpointInfo.LocalAddress.AddressFamily, SocketType.Dgram, ProtocolType.Udp))
			{
				try
				{
					udpClient.ReceiveTimeout = QueryTimeout;

					PrepareAndBindUdpSocket(endpointInfo, udpClient);

					EndPoint serverEndpoint = new IPEndPoint(endpointInfo.ServerAddress, _port);

					udpClient.SendTo(messageData, messageLength, SocketFlags.None, serverEndpoint);

					if (endpointInfo.IsMulticast)
						serverEndpoint = new IPEndPoint(udpClient.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, _port);

					byte[] buffer = new byte[65535];
					int length = udpClient.ReceiveFrom(buffer, 0, buffer.Length, SocketFlags.None, ref serverEndpoint);

					responderAddress = ((IPEndPoint) serverEndpoint).Address;

					byte[] res = new byte[length];
					Buffer.BlockCopy(buffer, 0, res, 0, length);
					return res;
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);
					responderAddress = default(IPAddress);
					return null;
				}
			}
		}

		private void PrepareAndBindUdpSocket(DnsClientEndpointInfo endpointInfo, System.Net.Sockets.Socket udpClient)
		{
			if (endpointInfo.IsMulticast)
			{
				udpClient.Bind(new IPEndPoint(endpointInfo.LocalAddress, 0));
			}
			else
			{
				udpClient.Connect(endpointInfo.ServerAddress, _port);
			}
		}

		private byte[] QueryByTcp(IPAddress nameServer, byte[] messageData, int messageLength, ref TcpClient tcpClient, ref NetworkStream tcpStream, out IPAddress responderAddress)
		{
			responderAddress = nameServer;

			IPEndPoint endPoint = new IPEndPoint(nameServer, _port);

			try
			{
				if (tcpClient == null)
				{
					tcpClient = new TcpClient(nameServer.AddressFamily)
					{
						ReceiveTimeout = QueryTimeout,
						SendTimeout = QueryTimeout
					};

					tcpClient.Connect(endPoint);
					tcpStream = tcpClient.GetStream();
				}

				int tmp = 0;
				byte[] lengthBuffer = new byte[2];

				if (messageLength > 0)
				{
					DnsMessageBase.EncodeUShort(lengthBuffer, ref tmp, (ushort) messageLength);

					tcpStream.Write(lengthBuffer, 0, 2);
					tcpStream.Write(messageData, 0, messageLength);
				}

				lengthBuffer[0] = (byte) tcpStream.ReadByte();
				lengthBuffer[1] = (byte) tcpStream.ReadByte();

				tmp = 0;
				int length = DnsMessageBase.ParseUShort(lengthBuffer, ref tmp);

				byte[] resultData = new byte[length];

				int readBytes = 0;

				while (readBytes < length)
				{
					readBytes += tcpStream.Read(resultData, readBytes, length - readBytes);
				}

				return resultData;
			}
			catch (Exception e)
			{
				Trace.TraceError("Error on dns query: " + e);
				return null;
			}
		}

		protected IAsyncResult BeginSendMessage<TMessage>(TMessage message, AsyncCallback requestCallback, object state)
			where TMessage : DnsMessageBase, new()
		{
			return BeginSendMessage(message, GetEndpointInfos<TMessage>(), requestCallback, state);
		}

		protected IAsyncResult BeginSendMessageParallel<TMessage>(TMessage message, AsyncCallback requestCallback, object state)
			where TMessage : DnsMessageBase, new()
		{
			List<DnsClientEndpointInfo> endpointInfos = GetEndpointInfos<TMessage>();

			DnsClientParallelAsyncState<TMessage> asyncResult =
				new DnsClientParallelAsyncState<TMessage>
				{
					UserCallback = requestCallback,
					AsyncState = state,
					Responses = new List<TMessage>(),
					ResponsesToReceive = endpointInfos.Count
				};

			foreach (var endpointInfo in endpointInfos)
			{
				DnsClientParallelState<TMessage> parallelState = new DnsClientParallelState<TMessage> { ParallelMessageAsyncState = asyncResult };

				lock (parallelState.Lock)
				{
					parallelState.SingleMessageAsyncResult = BeginSendMessage(message, new List<DnsClientEndpointInfo> { endpointInfo }, SendMessageFinished<TMessage>, parallelState);
				}
			}
			return asyncResult;
		}

		private void SendMessageFinished<TMessage>(IAsyncResult ar)
			where TMessage : DnsMessageBase, new()
		{
			DnsClientParallelState<TMessage> state = (DnsClientParallelState<TMessage>) ar.AsyncState;

			List<TMessage> responses;

			lock (state.Lock)
			{
				responses = EndSendMessage<TMessage>(state.SingleMessageAsyncResult);
			}

			lock (state.ParallelMessageAsyncState.Responses)
			{
				state.ParallelMessageAsyncState.Responses.AddRange(responses);
				state.ParallelMessageAsyncState.ResponsesToReceive--;

				if (state.ParallelMessageAsyncState.ResponsesToReceive == 0)
					state.ParallelMessageAsyncState.SetCompleted();
			}
		}

		private IAsyncResult BeginSendMessage<TMessage>(TMessage message, List<DnsClientEndpointInfo> endpointInfos, AsyncCallback requestCallback, object state)
			where TMessage : DnsMessageBase, new()
		{
			DnsClientAsyncState<TMessage> asyncResult =
				new DnsClientAsyncState<TMessage>
				{
					Query = message,
					Responses = new List<TMessage>(),
					UserCallback = requestCallback,
					AsyncState = state,
					EndpointInfoIndex = 0
				};

			PrepareMessage(message, out asyncResult.QueryLength, out asyncResult.QueryData, out asyncResult.TSigKeySelector, out asyncResult.TSigOriginalMac);
			asyncResult.EndpointInfos = endpointInfos;

			if ((asyncResult.QueryLength > MaximumQueryMessageSize) || message.IsTcpUsingRequested)
			{
				TcpBeginConnect(asyncResult);
			}
			else
			{
				UdpBeginSend(asyncResult);
			}

			return asyncResult;
		}

		private List<DnsClientEndpointInfo> GetEndpointInfos<TMessage>() where TMessage : DnsMessageBase, new()
		{
			List<DnsClientEndpointInfo> endpointInfos;
			if (_isAnyServerMulticast)
			{
				var localIPs = NetworkInterface.GetAllNetworkInterfaces()
				                               .Where(n => n.SupportsMulticast && (n.OperationalStatus == OperationalStatus.Up) && (n.NetworkInterfaceType != NetworkInterfaceType.Loopback))
				                               .SelectMany(n => n.GetIPProperties().UnicastAddresses.Select(a => a.Address))
				                               .Where(a => !IPAddress.IsLoopback(a) && ((a.AddressFamily == AddressFamily.InterNetwork) || a.IsIPv6LinkLocal))
				                               .ToList();

				endpointInfos = _servers
					.SelectMany(
						s =>
						{
							if (s.IsMulticast())
							{
								return localIPs
									.Where(l => l.AddressFamily == s.AddressFamily)
									.Select(
										l => new DnsClientEndpointInfo
										{
											IsMulticast = true,
											ServerAddress = s,
											LocalAddress = l
										});
							}
							else
							{
								return new[]
								{
									new DnsClientEndpointInfo
									{
										IsMulticast = false,
										ServerAddress = s,
										LocalAddress = s.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any
									}
								};
							}
						}).ToList();
			}
			else
			{
				endpointInfos = _servers
					.Select(
						s => new DnsClientEndpointInfo
						{
							IsMulticast = false,
							ServerAddress = s,
							LocalAddress = s.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any
						}
					).ToList();
			}
			return endpointInfos;
		}

		protected List<TMessage> EndSendMessage<TMessage>(IAsyncResult ar)
			where TMessage : DnsMessageBase, new()
		{
			DnsClientAsyncState<TMessage> state = (DnsClientAsyncState<TMessage>) ar;
			return state.Responses;
		}

		protected List<TMessage> EndSendMessageParallel<TMessage>(IAsyncResult ar)
			where TMessage : DnsMessageBase, new()
		{
			DnsClientParallelAsyncState<TMessage> state = (DnsClientParallelAsyncState<TMessage>) ar;
			return state.Responses;
		}

		private void UdpBeginSend<TMessage>(DnsClientAsyncState<TMessage> state)
			where TMessage : DnsMessageBase, new()
		{
			if (state.EndpointInfoIndex == state.EndpointInfos.Count)
			{
				state.UdpClient = null;
				state.UdpEndpoint = null;
				state.SetCompleted();
				return;
			}

			try
			{
				DnsClientEndpointInfo endpointInfo = state.EndpointInfos[state.EndpointInfoIndex];

				state.UdpEndpoint = new IPEndPoint(endpointInfo.ServerAddress, _port);

				state.UdpClient = new System.Net.Sockets.Socket(state.UdpEndpoint.AddressFamily, SocketType.Dgram, ProtocolType.Udp);

				PrepareAndBindUdpSocket(endpointInfo, state.UdpClient);

				state.TimedOut = false;
				state.TimeRemaining = QueryTimeout;

				IAsyncResult asyncResult = state.UdpClient.BeginSendTo(state.QueryData, 0, state.QueryLength, SocketFlags.None, state.UdpEndpoint, UdpSendCompleted<TMessage>, state);
				state.Timer = new Timer(UdpTimedOut<TMessage>, asyncResult, state.TimeRemaining, Timeout.Infinite);
			}
			catch (Exception e)
			{
				Trace.TraceError("Error on dns query: " + e);

				try
				{
					state.UdpClient.Close();
					state.Timer.Dispose();
				}
				catch {}

				state.EndpointInfoIndex++;
				UdpBeginSend(state);
			}
		}

		private static void UdpTimedOut<TMessage>(object ar)
			where TMessage : DnsMessageBase, new()
		{
			IAsyncResult asyncResult = (IAsyncResult) ar;

			if (!asyncResult.IsCompleted)
			{
				DnsClientAsyncState<TMessage> state = (DnsClientAsyncState<TMessage>) asyncResult.AsyncState;
				state.TimedOut = true;
				state.UdpClient.Close();
			}
		}

		private void UdpSendCompleted<TMessage>(IAsyncResult ar)
			where TMessage : DnsMessageBase, new()
		{
			DnsClientAsyncState<TMessage> state = (DnsClientAsyncState<TMessage>) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.EndpointInfoIndex++;
				UdpBeginSend(state);
			}
			else
			{
				try
				{
					state.UdpClient.EndSendTo(ar);

					state.Buffer = new byte[65535];

					if (state.EndpointInfos[state.EndpointInfoIndex].IsMulticast)
						state.UdpEndpoint = new IPEndPoint(state.UdpClient.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, _port);

					IAsyncResult asyncResult = state.UdpClient.BeginReceiveFrom(state.Buffer, 0, state.Buffer.Length, SocketFlags.None, ref state.UdpEndpoint, UdpReceiveCompleted<TMessage>, state);
					state.Timer = new Timer(UdpTimedOut<TMessage>, asyncResult, state.TimeRemaining, Timeout.Infinite);
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);

					try
					{
						state.UdpClient.Close();
						state.Timer.Dispose();
					}
					catch {}

					state.EndpointInfoIndex++;
					UdpBeginSend(state);
				}
			}
		}

		private void UdpReceiveCompleted<TMessage>(IAsyncResult ar)
			where TMessage : DnsMessageBase, new()
		{
			DnsClientAsyncState<TMessage> state = (DnsClientAsyncState<TMessage>) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.EndpointInfoIndex++;
				UdpBeginSend(state);
			}
			else
			{
				try
				{
					int length = state.UdpClient.EndReceiveFrom(ar, ref state.UdpEndpoint);
					byte[] responseData = new byte[length];
					Buffer.BlockCopy(state.Buffer, 0, responseData, 0, length);

					TMessage response = DnsMessageBase.Parse<TMessage>(responseData, state.TSigKeySelector, state.TSigOriginalMac);

					if (AreMultipleResponsesAllowedInParallelMode)
					{
						if (ValidateResponse(state.Query, response))
						{
							if (response.IsTcpResendingRequested)
							{
								TcpBeginConnect<TMessage>(state.CreateTcpCloneWithoutCallback(), ((IPEndPoint) state.UdpEndpoint).Address);
							}
							else
							{
								state.Responses.Add(response);
							}
						}

						state.Buffer = new byte[65535];

						if (state.EndpointInfos[state.EndpointInfoIndex].IsMulticast)
							state.UdpEndpoint = new IPEndPoint(state.UdpClient.AddressFamily == AddressFamily.InterNetwork ? IPAddress.Any : IPAddress.IPv6Any, _port);

						IAsyncResult asyncResult = state.UdpClient.BeginReceiveFrom(state.Buffer, 0, state.Buffer.Length, SocketFlags.None, ref state.UdpEndpoint, UdpReceiveCompleted<TMessage>, state);
						state.Timer = new Timer(UdpTimedOut<TMessage>, asyncResult, state.TimeRemaining, Timeout.Infinite);
					}
					else
					{
						state.UdpClient.Close();
						state.UdpClient = null;
						state.UdpEndpoint = null;

						if (!ValidateResponse(state.Query, response) || (response.ReturnCode == ReturnCode.ServerFailure))
						{
							state.EndpointInfoIndex++;
							UdpBeginSend(state);
						}
						else
						{
							if (response.IsTcpResendingRequested)
							{
								TcpBeginConnect<TMessage>(state, ((IPEndPoint) state.UdpEndpoint).Address);
							}
							else
							{
								state.Responses.Add(response);
								state.SetCompleted();
							}
						}
					}
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);

					try
					{
						state.UdpClient.Close();
						state.Timer.Dispose();
					}
					catch {}

					state.EndpointInfoIndex++;
					UdpBeginSend(state);
				}
			}
		}

		private void TcpBeginConnect<TMessage>(DnsClientAsyncState<TMessage> state)
			where TMessage : DnsMessageBase, new()
		{
			if (state.EndpointInfoIndex == state.EndpointInfos.Count)
			{
				state.TcpStream = null;
				state.TcpClient = null;
				state.SetCompleted();
				return;
			}

			TcpBeginConnect(state, state.EndpointInfos[state.EndpointInfoIndex].ServerAddress);
		}

		private void TcpBeginConnect<TMessage>(DnsClientAsyncState<TMessage> state, IPAddress server)
			where TMessage : DnsMessageBase, new()
		{
			if (state.EndpointInfoIndex == state.EndpointInfos.Count)
			{
				state.TcpStream = null;
				state.TcpClient = null;
				state.SetCompleted();
				return;
			}

			try
			{
				state.TcpClient = new TcpClient(server.AddressFamily);
				state.TimedOut = false;
				state.TimeRemaining = QueryTimeout;

				IAsyncResult asyncResult = state.TcpClient.BeginConnect(server, _port, TcpConnectCompleted<TMessage>, state);
				state.Timer = new Timer(TcpTimedOut<TMessage>, asyncResult, state.TimeRemaining, Timeout.Infinite);
			}
			catch (Exception e)
			{
				Trace.TraceError("Error on dns query: " + e);

				try
				{
					state.TcpClient.Close();
					state.Timer.Dispose();
				}
				catch {}

				state.EndpointInfoIndex++;
				TcpBeginConnect(state);
			}
		}

		private static void TcpTimedOut<TMessage>(object ar)
			where TMessage : DnsMessageBase, new()
		{
			IAsyncResult asyncResult = (IAsyncResult) ar;

			if (!asyncResult.IsCompleted)
			{
				DnsClientAsyncState<TMessage> state = (DnsClientAsyncState<TMessage>) asyncResult.AsyncState;
				state.PartialMessage = null;
				state.TimedOut = true;
				if (state.TcpStream != null)
					state.TcpStream.Close();
				state.TcpClient.Close();
			}
		}

		private void TcpConnectCompleted<TMessage>(IAsyncResult ar)
			where TMessage : DnsMessageBase, new()
		{
			DnsClientAsyncState<TMessage> state = (DnsClientAsyncState<TMessage>) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.EndpointInfoIndex++;
				TcpBeginConnect(state);
			}
			else
			{
				try
				{
					state.TcpClient.EndConnect(ar);

					state.TcpStream = state.TcpClient.GetStream();

					int tmp = 0;

					state.Buffer = new byte[2];
					DnsMessageBase.EncodeUShort(state.Buffer, ref tmp, (ushort) state.QueryLength);

					IAsyncResult asyncResult = state.TcpStream.BeginWrite(state.Buffer, 0, 2, TcpSendLengthCompleted<TMessage>, state);
					state.Timer = new Timer(TcpTimedOut<TMessage>, asyncResult, state.TimeRemaining, Timeout.Infinite);
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);

					try
					{
						state.TcpClient.Close();
						state.Timer.Dispose();
					}
					catch {}

					state.EndpointInfoIndex++;
					TcpBeginConnect(state);
				}
			}
		}

		private void TcpSendLengthCompleted<TMessage>(IAsyncResult ar)
			where TMessage : DnsMessageBase, new()
		{
			DnsClientAsyncState<TMessage> state = (DnsClientAsyncState<TMessage>) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.EndpointInfoIndex++;
				TcpBeginConnect(state);
			}
			else
			{
				try
				{
					state.TcpStream.EndWrite(ar);

					IAsyncResult asyncResult = state.TcpStream.BeginWrite(state.QueryData, 0, state.QueryLength, TcpSendCompleted<TMessage>, state);
					state.Timer = new Timer(TcpTimedOut<TMessage>, asyncResult, state.TimeRemaining, Timeout.Infinite);
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);

					try
					{
						state.TcpClient.Close();
						state.Timer.Dispose();
					}
					catch {}

					state.EndpointInfoIndex++;
					TcpBeginConnect(state);
				}
			}
		}

		private void TcpSendCompleted<TMessage>(IAsyncResult ar)
			where TMessage : DnsMessageBase, new()
		{
			DnsClientAsyncState<TMessage> state = (DnsClientAsyncState<TMessage>) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.EndpointInfoIndex++;
				TcpBeginConnect(state);
			}
			else
			{
				try
				{
					state.TcpStream.EndWrite(ar);

					state.TcpBytesToReceive = 2;

					IAsyncResult asyncResult = state.TcpStream.BeginRead(state.Buffer, 0, 2, TcpReceiveLengthCompleted<TMessage>, state);
					state.Timer = new Timer(TcpTimedOut<TMessage>, asyncResult, state.TimeRemaining, Timeout.Infinite);
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);

					try
					{
						state.TcpClient.Close();
						state.Timer.Dispose();
					}
					catch {}

					state.EndpointInfoIndex++;
					TcpBeginConnect(state);
				}
			}
		}

		private void TcpReceiveLengthCompleted<TMessage>(IAsyncResult ar)
			where TMessage : DnsMessageBase, new()
		{
			DnsClientAsyncState<TMessage> state = (DnsClientAsyncState<TMessage>) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.EndpointInfoIndex++;
				TcpBeginConnect(state);
			}
			else
			{
				try
				{
					state.TcpBytesToReceive -= state.TcpStream.EndRead(ar);

					if (state.TcpBytesToReceive > 0)
					{
						IAsyncResult asyncResult = state.TcpStream.BeginRead(state.Buffer, 2 - state.TcpBytesToReceive, state.TcpBytesToReceive, TcpReceiveLengthCompleted<TMessage>, state);
						state.Timer = new Timer(TcpTimedOut<TMessage>, asyncResult, state.TimeRemaining, Timeout.Infinite);
					}
					else
					{
						int tmp = 0;
						int responseLength = DnsMessageBase.ParseUShort(state.Buffer, ref tmp);

						state.Buffer = new byte[responseLength];
						state.TcpBytesToReceive = responseLength;

						IAsyncResult asyncResult = state.TcpStream.BeginRead(state.Buffer, 0, responseLength, TcpReceiveCompleted<TMessage>, state);
						state.Timer = new Timer(TcpTimedOut<TMessage>, asyncResult, state.TimeRemaining, Timeout.Infinite);
					}
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);

					try
					{
						state.TcpClient.Close();
						state.Timer.Dispose();
					}
					catch {}

					state.EndpointInfoIndex++;
					TcpBeginConnect(state);
				}
			}
		}

		private void TcpReceiveCompleted<TMessage>(IAsyncResult ar)
			where TMessage : DnsMessageBase, new()
		{
			DnsClientAsyncState<TMessage> state = (DnsClientAsyncState<TMessage>) ar.AsyncState;

			if (state.Timer != null)
				state.Timer.Dispose();

			if (state.TimedOut)
			{
				state.EndpointInfoIndex++;
				TcpBeginConnect(state);
			}
			else
			{
				try
				{
					state.TcpBytesToReceive -= state.TcpStream.EndRead(ar);

					if (state.TcpBytesToReceive > 0)
					{
						IAsyncResult asyncResult = state.TcpStream.BeginRead(state.Buffer, state.Buffer.Length - state.TcpBytesToReceive, state.TcpBytesToReceive, TcpReceiveCompleted<TMessage>, state);
						state.Timer = new Timer(TcpTimedOut<TMessage>, asyncResult, state.TimeRemaining, Timeout.Infinite);
					}
					else
					{
						byte[] buffer = state.Buffer;
						state.Buffer = null;

						TMessage response = DnsMessageBase.Parse<TMessage>(buffer, state.TSigKeySelector, state.TSigOriginalMac);

						if (!ValidateResponse(state.Query, response) || (response.ReturnCode == ReturnCode.ServerFailure))
						{
							state.EndpointInfoIndex++;
							state.PartialMessage = null;
							state.TcpStream.Close();
							state.TcpClient.Close();
							state.TcpStream = null;
							state.TcpClient = null;
							TcpBeginConnect(state);
						}
						else
						{
							bool isSubsequentResponseMessage = (state.PartialMessage != null);

							if (isSubsequentResponseMessage)
							{
								state.PartialMessage.AnswerRecords.AddRange(response.AnswerRecords);
							}
							else
							{
								state.PartialMessage = response;
							}

							if (response.IsTcpNextMessageWaiting(isSubsequentResponseMessage))
							{
								state.TcpBytesToReceive = 2;
								state.Buffer = new byte[2];

								IAsyncResult asyncResult = state.TcpStream.BeginRead(state.Buffer, 0, 2, TcpReceiveLengthCompleted<TMessage>, state);
								state.Timer = new Timer(TcpTimedOut<TMessage>, asyncResult, state.TimeRemaining, Timeout.Infinite);
							}
							else
							{
								state.TcpStream.Close();
								state.TcpClient.Close();
								state.TcpStream = null;
								state.TcpClient = null;

								state.Responses.Add(state.PartialMessage);
								state.SetCompleted();
							}
						}
					}
				}
				catch (Exception e)
				{
					Trace.TraceError("Error on dns query: " + e);

					try
					{
						state.TcpClient.Close();
						state.Timer.Dispose();
					}
					catch {}

					state.EndpointInfoIndex++;
					TcpBeginConnect(state);
				}
			}
		}
	}
}