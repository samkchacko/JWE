
using Microsoft.IdentityModel.Tokens;
using System;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using System.IdentityModel.Tokens.Jwt;
using System.Collections.Generic;
using System.Text;

namespace JWE
{
	class Program
	{
		static void Main(string[] args)
		{
			var token = TokenHelper.GenerateToken();
			Console.WriteLine("Generated Encrypted Token:");
			Console.WriteLine(token);
			var principal = TokenHelper.DecodeToken(token);
			if (principal != null)
			{
				Console.WriteLine("Decoded Claims:");
				foreach (var claim in principal.Claims)
				{
					Console.WriteLine($"{claim.Type}: {claim.Value}");
				}
			}
			else
			{
				Console.WriteLine("Failed to decode token.");
			}
			Console.ReadLine();
		}
	}

	public static class TokenHelper
	{
		public static string GenerateToken()
		{
			var handler = new JwtSecurityTokenHandler();

			string privateKeyPath = "JWT/mykey.pem"; // Private key for signing
			string publicKeyPath = "JWT/mypublickey.pem"; // Public key for encryption
			var signingKey = LoadKey(privateKeyPath); // For signing
			var encryptionKey = LoadKey(publicKeyPath); // For encryption

			// Create RsaSecurityKey with a new CryptoProviderFactory
			var rsaSecurityKey = new RsaSecurityKey(encryptionKey)
			{
				KeyId = Guid.NewGuid().ToString(),
				CryptoProviderFactory = new CryptoProviderFactory
				{
					CacheSignatureProviders = false // Only this is valid in .NET 6
				}
			};

			// Use that key in EncryptingCredentials
			var encryptingCredentials = new EncryptingCredentials(
				rsaSecurityKey,
				SecurityAlgorithms.RsaOAEP,
				SecurityAlgorithms.Aes128CbcHmacSha256
			);
			var signingCredentials = new SigningCredentials(
						new RsaSecurityKey(signingKey),
						SecurityAlgorithms.RsaSha256
						);

			var claims = new List<Claim>
			{
				new Claim("userId", "Sam"),
				new Claim(ClaimTypes.Role, "Developer"),
				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
				new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
			};

			var descriptor = new SecurityTokenDescriptor
			{
				Subject = new ClaimsIdentity(claims),
				Issuer = "https://Sam",
				Audience = "https://Speridian:5001",
				Expires = DateTime.UtcNow.AddMinutes(60),
				EncryptingCredentials = encryptingCredentials,
				SigningCredentials= signingCredentials
			};

			var token = handler.CreateToken(descriptor);
			return handler.WriteToken(token);
		}
		public static ClaimsPrincipal DecodeToken(string token)
		{
			var handler = new JwtSecurityTokenHandler();
			var privateKeyPath = "JWT/mykey.pem"; // Private key for signing
			var publicKeyPath = "JWT/mypublickey.pem"; // Public key for encryption
			var rsaDecryptionKey = new RsaSecurityKey(LoadKey(privateKeyPath));
			var rsaVerificationKey = new RsaSecurityKey(LoadKey(publicKeyPath));

			var tokenValidationParameters = new TokenValidationParameters
			{
				IssuerSigningKey = rsaVerificationKey,
				TokenDecryptionKey = rsaDecryptionKey,
				ValidateIssuer = true,
				ValidIssuer = "https://Sam",
				ValidateAudience = true,
				ValidAudience = "https://Speridian:5001",
				ValidateLifetime = true,
				ClockSkew = TimeSpan.Zero
			};
			try
			{
				var principal = handler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);
				return principal;
			}
			catch (Exception ex)
			{
				Console.WriteLine($"Error validating token: {ex.Message}");
				return null;
			}
		}
		private static RSA LoadKey(string path)
		{
			try
			{
				var publicKeyText = File.ReadAllText(path);
				var rsa = RSA.Create();
				rsa.ImportFromPem(publicKeyText.ToCharArray());
				return rsa;
			}
			catch (Exception ex)
			{
				Console.WriteLine($"Error loading public key: {ex.Message}");
				return null;
			}
		}
	}
}