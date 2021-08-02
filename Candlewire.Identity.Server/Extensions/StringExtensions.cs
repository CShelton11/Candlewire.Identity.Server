using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;

namespace Candlewire.Identity.Server.Extensions
{
	public static class StringExtensions
	{
		private const String Key = "ZCAR10DADF12459DKK9AABBB432F84WERTAA8U34KJ409G0SV33";
		private const String Vector = "6A7FRTTYT14UYYTG";
		private const Int32 keysize = 256;

		public static String Encrypt(this String text)
		{
			var initVectorBytes = Encoding.UTF8.GetBytes(Vector);
			var plainTextBytes = Encoding.UTF8.GetBytes(text);
			var password = new PasswordDeriveBytes(Key, null);
			var keyBytes = password.GetBytes(keysize / 8);
			var symmetricKey = new RijndaelManaged() { Mode = CipherMode.CBC };
			var encryptor = symmetricKey.CreateEncryptor(keyBytes, initVectorBytes);
			var memoryStream = new MemoryStream();
			var cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write);
			cryptoStream.Write(plainTextBytes, 0, plainTextBytes.Length);
			cryptoStream.FlushFinalBlock();
			var cipherTextBytes = memoryStream.ToArray();
			memoryStream.Close();
			cryptoStream.Close();
			return Convert.ToBase64String(cipherTextBytes);
		}

		public static String Decrypt(this String text)
		{
			var initVectorBytes = Encoding.UTF8.GetBytes(Vector);
			var cipherTextBytes = Convert.FromBase64String(text);
			var password = new PasswordDeriveBytes(Key, null);
			var keyBytes = password.GetBytes(keysize / 8);
			var symmetricKey = new RijndaelManaged();
			symmetricKey.Mode = CipherMode.CBC;
			var decryptor = symmetricKey.CreateDecryptor(keyBytes, initVectorBytes);
			var memoryStream = new System.IO.MemoryStream(cipherTextBytes);
			var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read);
			var plainTextBytes = new byte[cipherTextBytes.Length];
			var decryptedByteCount = cryptoStream.Read(plainTextBytes, 0, plainTextBytes.Length);
			memoryStream.Close();
			cryptoStream.Close();
			return Encoding.UTF8.GetString(plainTextBytes, 0, decryptedByteCount);
		}

		public static Boolean IsValidEmail(this String email)
		{
			if (string.IsNullOrWhiteSpace(email))
			{
				return false;
			}

			try
			{
				email = Regex.Replace(email, @"(@)(.+)$", DomainMapper, RegexOptions.None, TimeSpan.FromMilliseconds(200));
				string DomainMapper(Match match)
				{
					var idn = new IdnMapping();
					string domainName = idn.GetAscii(match.Groups[2].Value);
					return match.Groups[1].Value + domainName;
				}
			}
			catch (RegexMatchTimeoutException e)
			{
				return false;
			}
			catch (ArgumentException e)
			{
				return false;
			}

			try
			{
				return Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(250));
			}
			catch (RegexMatchTimeoutException)
			{
				return false;
			}
		}

		public static String GetDomainName(this String email)
        {
			return (email).Substring((email).IndexOf("@") + 1);
		}
	}
}
