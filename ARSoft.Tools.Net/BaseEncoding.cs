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

namespace ARSoft.Tools.Net
{
	/// <summary>
	///   <para>Extension class for encoding and decoding Base16, Base32 and Base64</para>
	///   <para>
	///     Defined in
	///     <see cref="!:http://tools.ietf.org/html/rfc4648">RFC 4648</see>
	///   </para>
	/// </summary>
	public static class BaseEncoding
	{
		#region Helper
		private static Dictionary<char, byte> GetAlphabet(string alphabet, bool isCaseIgnored)
		{
			Dictionary<char, byte> res = new Dictionary<char, byte>(isCaseIgnored ? 2 * alphabet.Length : alphabet.Length);

			for (byte i = 0; i < alphabet.Length; i++)
			{
				res[alphabet[i]] = i;
			}

			if (isCaseIgnored)
			{
				alphabet = alphabet.ToLowerInvariant();
				for (byte i = 0; i < alphabet.Length; i++)
				{
					res[alphabet[i]] = i;
				}
			}

			return res;
		}
		#endregion

		#region Base16
		private const string _BASE16_ALPHABET = "0123456789ABCDEF";
		private static readonly char[] _base16Alphabet = _BASE16_ALPHABET.ToCharArray();
		private static readonly Dictionary<char, byte> _base16ReverseAlphabet = GetAlphabet(_BASE16_ALPHABET, true);

		/// <summary>
		///   Decodes a Base16 string as described in <see cref="!:http://tools.ietf.org/html/rfc4648">RFC 4648</see> .
		/// </summary>
		/// <param name="inData"> An Base16 encoded string. </param>
		/// <returns> Decoded data </returns>
		public static byte[] FromBase16String(this string inData)
		{
			return inData.ToCharArray().FromBase16CharArray(0, inData.Length);
		}

		/// <summary>
		///   Decodes a Base16 char array as described in <see cref="!:http://tools.ietf.org/html/rfc4648">RFC 4648</see> .
		/// </summary>
		/// <param name="inData"> An Base16 encoded char array. </param>
		/// <param name="offset"> An offset in inData. </param>
		/// <param name="length"> The number of elements of inData to decode. </param>
		/// <returns> Decoded data </returns>
		public static byte[] FromBase16CharArray(this char[] inData, int offset, int length)
		{
			byte[] res = new byte[length / 2];

			int inPos = offset;
			int outPos = 0;

			while (inPos < offset + length)
			{
				res[outPos++] = (byte) ((_base16ReverseAlphabet[inData[inPos++]] << 4) + _base16ReverseAlphabet[inData[inPos++]]);
			}

			return res;
		}

		/// <summary>
		///   Converts a byte array to its corresponding Base16 encoding described in
		///   <see
		///     cref="!:http://tools.ietf.org/html/rfc4648">
		///     RFC 4648
		///   </see>
		///   .
		/// </summary>
		/// <param name="inArray"> An array of 8-bit unsigned integers. </param>
		/// <returns> Encoded string </returns>
		public static string ToBase16String(this byte[] inArray)
		{
			return inArray.ToBase16String(0, inArray.Length);
		}

		/// <summary>
		///   Converts a byte array to its corresponding Base16 encoding described in
		///   <see
		///     cref="!:http://tools.ietf.org/html/rfc4648">
		///     RFC 4648
		///   </see>
		///   .
		/// </summary>
		/// <param name="inArray"> An array of 8-bit unsigned integers. </param>
		/// <param name="offset"> An offset in inArray. </param>
		/// <param name="length"> The number of elements of inArray to convert. </param>
		/// <returns> Encoded string </returns>
		public static string ToBase16String(this byte[] inArray, int offset, int length)
		{
			char[] outData = new char[length * 2];

			int inPos = offset;
			int inEnd = offset + length;
			int outPos = 0;

			while (inPos < inEnd)
			{
				outData[outPos++] = _base16Alphabet[(inArray[inPos] >> 4) & 0x0f];
				outData[outPos++] = _base16Alphabet[inArray[inPos++] & 0x0f];
			}

			return new string(outData);
		}
		#endregion

		#region Base32
		private const string _BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567=";
		private static readonly char[] _base32Alphabet = _BASE32_ALPHABET.ToCharArray();
		private static readonly Dictionary<char, byte> _base32ReverseAlphabet = GetAlphabet(_BASE32_ALPHABET, true);

		/// <summary>
		///   Decodes a Base32 string as described in <see cref="!:http://tools.ietf.org/html/rfc4648">RFC 4648</see> .
		/// </summary>
		/// <param name="inData"> An Base32 encoded string. </param>
		/// <returns> Decoded data </returns>
		public static byte[] FromBase32String(this string inData)
		{
			return inData.ToCharArray().FromBase32CharArray(0, inData.Length);
		}

		/// <summary>
		///   Decodes a Base32 char array as described in <see cref="!:http://tools.ietf.org/html/rfc4648">RFC 4648</see> .
		/// </summary>
		/// <param name="inData"> An Base32 encoded char array. </param>
		/// <param name="offset"> An offset in inData. </param>
		/// <param name="length"> The number of elements of inData to decode. </param>
		/// <returns> Decoded data </returns>
		public static byte[] FromBase32CharArray(this char[] inData, int offset, int length)
		{
			return inData.FromBase32CharArray(offset, length, _base32ReverseAlphabet);
		}

		/// <summary>
		///   Converts a byte array to its corresponding Base32 encoding described in
		///   <see
		///     cref="!:http://tools.ietf.org/html/rfc4648">
		///     RFC 4648
		///   </see>
		///   .
		/// </summary>
		/// <param name="inArray"> An array of 8-bit unsigned integers. </param>
		/// <returns> Encoded string </returns>
		public static string ToBase32String(this byte[] inArray)
		{
			return inArray.ToBase32String(0, inArray.Length);
		}

		/// <summary>
		///   Converts a byte array to its corresponding Base32 encoding described in
		///   <see
		///     cref="!:http://tools.ietf.org/html/rfc4648">
		///     RFC 4648
		///   </see>
		///   .
		/// </summary>
		/// <param name="inArray"> An array of 8-bit unsigned integers. </param>
		/// <param name="offset"> An offset in inArray. </param>
		/// <param name="length"> The number of elements of inArray to convert. </param>
		/// <returns> Encoded string </returns>
		public static string ToBase32String(this byte[] inArray, int offset, int length)
		{
			return inArray.ToBase32String(offset, length, _base32Alphabet);
		}

		private const string _BASE32_HEX_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUV=";
		private static readonly char[] _base32HexAlphabet = _BASE32_HEX_ALPHABET.ToCharArray();
		private static readonly Dictionary<char, byte> _base32HexReverseAlphabet = GetAlphabet(_BASE32_HEX_ALPHABET, true);

		/// <summary>
		///   Decodes a Base32Hex string as described in <see cref="!:http://tools.ietf.org/html/rfc4648">RFC 4648</see> .
		/// </summary>
		/// <param name="inData"> An Base32Hex encoded string. </param>
		/// <returns> Decoded data </returns>
		public static byte[] FromBase32HexString(this string inData)
		{
			return inData.ToCharArray().FromBase32HexCharArray(0, inData.Length);
		}

		/// <summary>
		///   Decodes a Base32Hex char array as described in <see cref="!:http://tools.ietf.org/html/rfc4648">RFC 4648</see> .
		/// </summary>
		/// <param name="inData"> An Base32Hex encoded char array. </param>
		/// <param name="offset"> An offset in inData. </param>
		/// <param name="length"> The number of elements of inData to decode. </param>
		/// <returns> Decoded data </returns>
		public static byte[] FromBase32HexCharArray(this char[] inData, int offset, int length)
		{
			return inData.FromBase32CharArray(offset, length, _base32HexReverseAlphabet);
		}

		/// <summary>
		///   Converts a byte array to its corresponding Base32Hex encoding described in
		///   <see
		///     cref="!:http://tools.ietf.org/html/rfc4648">
		///     RFC 4648
		///   </see>
		///   .
		/// </summary>
		/// <param name="inArray"> An array of 8-bit unsigned integers. </param>
		/// <returns> Encoded string </returns>
		public static string ToBase32HexString(this byte[] inArray)
		{
			return inArray.ToBase32HexString(0, inArray.Length);
		}

		/// <summary>
		///   Converts a byte array to its corresponding Base32Hex encoding described in
		///   <see
		///     cref="!:http://tools.ietf.org/html/rfc4648">
		///     RFC 4648
		///   </see>
		///   .
		/// </summary>
		/// <param name="inArray"> An array of 8-bit unsigned integers. </param>
		/// <param name="offset"> An offset in inArray. </param>
		/// <param name="length"> The number of elements of inArray to convert. </param>
		/// <returns> Encoded string </returns>
		public static string ToBase32HexString(this byte[] inArray, int offset, int length)
		{
			return inArray.ToBase32String(offset, length, _base32HexAlphabet);
		}

		private static byte[] FromBase32CharArray(this char[] inData, int offset, int length, Dictionary<char, byte> alphabet)
		{
			int paddingCount = 0;
			while (paddingCount < 6)
			{
				if (alphabet[inData[offset + length - paddingCount - 1]] != 32)
					break;

				paddingCount++;
			}

			int remain;
			switch (paddingCount)
			{
				case 6:
					remain = 1;
					break;
				case 4:
					remain = 2;
					break;
				case 3:
					remain = 3;
					break;
				case 1:
					remain = 4;
					break;
				default:
					remain = 0;
					break;
			}

			int outSafeLength = (length - paddingCount) / 8 * 5;

			byte[] res = new byte[outSafeLength + remain];

			int inPos = offset;
			int outPos = 0;

			byte[] buffer = new byte[8];

			while (outPos < outSafeLength)
			{
				for (int i = 0; i < 8; i++)
				{
					buffer[i] = alphabet[inData[inPos++]];
				}

				res[outPos++] = (byte) ((buffer[0] << 3) | ((buffer[1] >> 2) & 0x07));
				res[outPos++] = (byte) (((buffer[1] >> 6) & 0xc0) | (buffer[2] << 1) | ((buffer[3] >> 4) & 0x01));
				res[outPos++] = (byte) (((buffer[3] << 4) & 0xf0) | ((buffer[4] >> 1) & 0x0f));
				res[outPos++] = (byte) (((buffer[4] << 7) & 0x80) | (buffer[5] << 2) | ((buffer[6] >> 3) & 0x03));
				res[outPos++] = (byte) (((buffer[6] << 5) & 0xe0) | buffer[7]);
			}

			if (remain > 0)
			{
				for (int i = 0; i < 8 - paddingCount; i++)
				{
					buffer[i] = alphabet[inData[inPos++]];
				}

				switch (remain)
				{
					case 1:
						res[outPos] = (byte) ((buffer[0] << 3) | ((buffer[1] >> 2) & 0x07));
						break;
					case 2:
						res[outPos++] = (byte) ((buffer[0] << 3) | ((buffer[1] >> 2) & 0x07));
						res[outPos] = (byte) (((buffer[1] >> 6) & 0xc0) | (buffer[2] << 1) | ((buffer[3] >> 4) & 0x01));
						break;
					case 3:
						res[outPos++] = (byte) ((buffer[0] << 3) | ((buffer[1] >> 2) & 0x07));
						res[outPos++] = (byte) (((buffer[1] >> 6) & 0xc0) | (buffer[2] << 1) | ((buffer[3] >> 4) & 0x01));
						res[outPos] = (byte) (((buffer[3] << 4) & 0xf0) | ((buffer[4] >> 1) & 0x0f));
						break;
					case 4:
						res[outPos++] = (byte) ((buffer[0] << 3) | ((buffer[1] >> 2) & 0x07));
						res[outPos++] = (byte) (((buffer[1] >> 6) & 0xc0) | (buffer[2] << 1) | ((buffer[3] >> 4) & 0x01));
						res[outPos++] = (byte) (((buffer[3] << 4) & 0xf0) | ((buffer[4] >> 1) & 0x0f));
						res[outPos] = (byte) (((buffer[4] << 7) & 0x80) | (buffer[5] << 2) | ((buffer[6] >> 3) & 0x03));
						break;
				}
			}

			return res;
		}

		private static string ToBase32String(this byte[] inArray, int offset, int length, char[] alphabet)
		{
			int inRemain = length % 5;
			int inSafeEnd = offset + length - inRemain;

			int outLength = length / 5 * 8 + ((inRemain == 0) ? 0 : 8);

			char[] outData = new char[outLength];
			int outPos = 0;

			int inPos = offset;
			while (inPos < inSafeEnd)
			{
				outData[outPos++] = alphabet[(inArray[inPos] & 0xf8) >> 3];
				outData[outPos++] = alphabet[((inArray[inPos] & 0x07) << 2) | ((inArray[++inPos] & 0xc0) >> 6)];
				outData[outPos++] = alphabet[((inArray[inPos] & 0x3e) >> 1)];
				outData[outPos++] = alphabet[((inArray[inPos] & 0x01) << 4) | ((inArray[++inPos] & 0xf0) >> 4)];
				outData[outPos++] = alphabet[((inArray[inPos] & 0x0f) << 1) | ((inArray[++inPos] & 0x80) >> 7)];
				outData[outPos++] = alphabet[((inArray[inPos] & 0x7c) >> 2)];
				outData[outPos++] = alphabet[((inArray[inPos] & 0x03) << 3) | ((inArray[++inPos] & 0xe0) >> 5)];
				outData[outPos++] = alphabet[inArray[inPos++] & 0x1f];
			}

			switch (inRemain)
			{
				case 1:
					outData[outPos++] = alphabet[(inArray[inPos] & 0xf8) >> 3];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x07) << 2)];
					outData[outPos++] = alphabet[32];
					outData[outPos++] = alphabet[32];
					outData[outPos++] = alphabet[32];
					outData[outPos++] = alphabet[32];
					outData[outPos++] = alphabet[32];
					outData[outPos] = alphabet[32];
					break;
				case 2:
					outData[outPos++] = alphabet[(inArray[inPos] & 0xf8) >> 3];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x07) << 2) | ((inArray[++inPos] & 0xc0) >> 6)];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x3e) >> 1)];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x01) << 4)];
					outData[outPos++] = alphabet[32];
					outData[outPos++] = alphabet[32];
					outData[outPos++] = alphabet[32];
					outData[outPos] = alphabet[32];
					break;
				case 3:
					outData[outPos++] = alphabet[(inArray[inPos] & 0xf8) >> 3];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x07) << 2) | ((inArray[++inPos] & 0xc0) >> 6)];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x3e) >> 1)];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x01) << 4) | ((inArray[++inPos] & 0xf0) >> 4)];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x0f) << 1)];
					outData[outPos++] = alphabet[32];
					outData[outPos++] = alphabet[32];
					outData[outPos] = alphabet[32];
					break;
				case 4:
					outData[outPos++] = alphabet[(inArray[inPos] & 0xf8) >> 3];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x07) << 2) | ((inArray[++inPos] & 0xc0) >> 6)];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x3e) >> 1)];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x01) << 4) | ((inArray[++inPos] & 0xf0) >> 4)];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x0f) << 1) | ((inArray[++inPos] & 0x80) >> 7)];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x7c) >> 2)];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x03) << 3)];
					outData[outPos] = alphabet[32];
					break;
			}

			return new string(outData);
		}
		#endregion

		#region Base64
		private const string _BASE64_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
		private static readonly char[] _base64Alphabet = _BASE64_ALPHABET.ToCharArray();
		private static readonly Dictionary<char, byte> _base64ReverseAlphabet = GetAlphabet(_BASE64_ALPHABET, false);

		/// <summary>
		///   Decodes a Base64 string as described in <see cref="!:http://tools.ietf.org/html/rfc4648">RFC 4648</see> .
		/// </summary>
		/// <param name="inData"> An Base64 encoded string. </param>
		/// <returns> Decoded data </returns>
		public static byte[] FromBase64String(this string inData)
		{
			return inData.ToCharArray().FromBase64CharArray(0, inData.Length);
		}

		/// <summary>
		///   Decodes a Base64 char array as described in <see cref="!:http://tools.ietf.org/html/rfc4648">RFC 4648</see> .
		/// </summary>
		/// <param name="inData"> An Base64 encoded char array. </param>
		/// <param name="offset"> An offset in inData. </param>
		/// <param name="length"> The number of elements of inData to decode. </param>
		/// <returns> Decoded data </returns>
		public static byte[] FromBase64CharArray(this char[] inData, int offset, int length)
		{
			return inData.FromBase64CharArray(offset, length, _base64ReverseAlphabet);
		}

		/// <summary>
		///   Converts a byte array to its corresponding Base64 encoding described in
		///   <see
		///     cref="!:http://tools.ietf.org/html/rfc4648">
		///     RFC 4648
		///   </see>
		///   .
		/// </summary>
		/// <param name="inArray"> An array of 8-bit unsigned integers. </param>
		/// <returns> Encoded string </returns>
		public static string ToBase64String(this byte[] inArray)
		{
			return inArray.ToBase64String(0, inArray.Length);
		}

		/// <summary>
		///   Converts a byte array to its corresponding Base64 encoding described in
		///   <see
		///     cref="!:http://tools.ietf.org/html/rfc4648">
		///     RFC 4648
		///   </see>
		///   .
		/// </summary>
		/// <param name="inArray"> An array of 8-bit unsigned integers. </param>
		/// <param name="offset"> An offset in inArray. </param>
		/// <param name="length"> The number of elements of inArray to convert. </param>
		/// <returns> Encoded string </returns>
		public static string ToBase64String(this byte[] inArray, int offset, int length)
		{
			return inArray.ToBase64String(offset, length, _base64Alphabet);
		}

		private const string _BASE64_URL_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_=";
		private static readonly char[] _base64UrlAlphabet = _BASE64_URL_ALPHABET.ToCharArray();
		private static readonly Dictionary<char, byte> _base64UrlReverseAlphabet = GetAlphabet(_BASE64_URL_ALPHABET, false);

		/// <summary>
		///   Decodes a Base64Url string as described in <see cref="!:http://tools.ietf.org/html/rfc4648">RFC 4648</see> .
		/// </summary>
		/// <param name="inData"> An Base64Url encoded string. </param>
		/// <returns> Decoded data </returns>
		public static byte[] FromBase64UrlString(this string inData)
		{
			return inData.ToCharArray().FromBase64UrlCharArray(0, inData.Length);
		}

		/// <summary>
		///   Decodes a Base64Url char array as described in <see cref="!:http://tools.ietf.org/html/rfc4648">RFC 4648</see> .
		/// </summary>
		/// <param name="inData"> An Base64Url encoded char array. </param>
		/// <param name="offset"> An offset in inData. </param>
		/// <param name="length"> The number of elements of inData to decode. </param>
		/// <returns> Decoded data </returns>
		public static byte[] FromBase64UrlCharArray(this char[] inData, int offset, int length)
		{
			return inData.FromBase64CharArray(offset, length, _base64UrlReverseAlphabet);
		}

		/// <summary>
		///   Converts a byte array to its corresponding Base64Url encoding described in
		///   <see
		///     cref="!:http://tools.ietf.org/html/rfc4648">
		///     RFC 4648
		///   </see>
		///   .
		/// </summary>
		/// <param name="inArray"> An array of 8-bit unsigned integers. </param>
		/// <returns> Encoded string </returns>
		public static string ToBase64UrlString(this byte[] inArray)
		{
			return inArray.ToBase64UrlString(0, inArray.Length);
		}

		/// <summary>
		///   Converts a byte array to its corresponding Base64Url encoding described in
		///   <see
		///     cref="!:http://tools.ietf.org/html/rfc4648">
		///     RFC 4648
		///   </see>
		///   .
		/// </summary>
		/// <param name="inArray"> An array of 8-bit unsigned integers. </param>
		/// <param name="offset"> An offset in inArray. </param>
		/// <param name="length"> The number of elements of inArray to convert. </param>
		/// <returns> Encoded string </returns>
		public static string ToBase64UrlString(this byte[] inArray, int offset, int length)
		{
			return inArray.ToBase64String(offset, length, _base64UrlAlphabet);
		}

		private static byte[] FromBase64CharArray(this char[] inData, int offset, int length, Dictionary<char, byte> alphabet)
		{
			int paddingCount;
			int remain;

			if (alphabet[inData[offset + length - 2]] == 64)
			{
				paddingCount = 2;
				remain = 1;
			}
			else if (alphabet[inData[offset + length - 1]] == 64)
			{
				paddingCount = 1;
				remain = 2;
			}
			else
			{
				paddingCount = 0;
				remain = 0;
			}

			int outSafeLength = (length - paddingCount) / 4 * 3;

			byte[] res = new byte[outSafeLength + remain];

			int inPos = offset;
			int outPos = 0;

			byte[] buffer = new byte[4];

			while (outPos < outSafeLength)
			{
				for (int i = 0; i < 4; i++)
				{
					buffer[i] = alphabet[inData[inPos++]];
				}

				res[outPos++] = (byte) ((buffer[0] << 2) | ((buffer[1] >> 4) & 0x03));
				res[outPos++] = (byte) (((buffer[1] << 4) & 0xf0) | ((buffer[2] >> 2) & 0x0f));
				res[outPos++] = (byte) (((buffer[2] << 6) & 0xc0) | (buffer[3] & 0x3f));
			}

			if (remain > 0)
			{
				for (int i = 0; i < 4 - paddingCount; i++)
				{
					buffer[i] = alphabet[inData[inPos++]];
				}

				switch (remain)
				{
					case 1:
						res[outPos] = (byte) ((buffer[0] << 2) | ((buffer[1] >> 4) & 0x03));
						break;
					case 2:
						res[outPos++] = (byte) ((buffer[0] << 2) | ((buffer[1] >> 4) & 0x03));
						res[outPos] = (byte) (((buffer[1] << 4) & 0xf0) | ((buffer[2] >> 2) & 0x0f));
						break;
				}
			}

			return res;
		}

		private static string ToBase64String(this byte[] inArray, int offset, int length, char[] alphabet)
		{
			int inRemain = length % 3;
			int inSafeEnd = offset + length - inRemain;

			int outLength = length / 3 * 4 + ((inRemain == 0) ? 0 : 4);

			char[] outData = new char[outLength];
			int outPos = 0;

			int inPos = offset;
			while (inPos < inSafeEnd)
			{
				outData[outPos++] = alphabet[(inArray[inPos] & 0xfc) >> 2];
				outData[outPos++] = alphabet[((inArray[inPos] & 0x03) << 4) | ((inArray[++inPos] & 0xf0) >> 4)];
				outData[outPos++] = alphabet[((inArray[inPos] & 0x0f) << 2) | ((inArray[++inPos] & 0xc0) >> 6)];
				outData[outPos++] = alphabet[inArray[inPos++] & 0x3f];
			}

			switch (inRemain)
			{
				case 1:
					outData[outPos++] = alphabet[(inArray[inPos] & 0xfc) >> 2];
					outData[outPos++] = alphabet[(inArray[inPos] & 0x03) << 4];
					outData[outPos++] = alphabet[64];
					outData[outPos] = alphabet[64];
					break;
				case 2:
					outData[outPos++] = alphabet[(inArray[inPos] & 0xfc) >> 2];
					outData[outPos++] = alphabet[((inArray[inPos] & 0x03) << 4) | ((inArray[++inPos] & 0xf0) >> 4)];
					outData[outPos++] = alphabet[(inArray[inPos] & 0x0f) << 2];
					outData[outPos] = alphabet[64];
					break;
			}

			return new string(outData);
		}
		#endregion
	}
}