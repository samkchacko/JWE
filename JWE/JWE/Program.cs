//using Microsoft.IdentityModel.JsonWebTokens;
//using Microsoft.IdentityModel.Tokens;
//using System;
//using System.Security.Claims;
//using System.Security.Cryptography;
//using System.IO;

//namespace JWE
//{
//	class Program
//	{
//		static void Main(string[] args)
//		{
//			TokenHelper tokenHelper = new TokenHelper();
//			Console.WriteLine("Generated Encrypted Token:");
//			Console.WriteLine(tokenHelper.GenerateToken());
//		}
//	}

//	public class TokenHelper
//	{
//		public string GenerateToken()
//		{
//			var handler = new JsonWebTokenHandler();

//			// Load RSA keys from PEM files
//			string privateKeyPath = "JWT/mykey.pem"; // Private key for signing
//			string publicKeyPath = "JWT/mypublickey.pem"; // Public key for encryption
//			var signingKey = LoadKey(privateKeyPath); // For signing
//			var encryptionKey = LoadKey(publicKeyPath); // For encryption

//			if (signingKey == null || encryptionKey == null)
//				throw new Exception("RSA key loading failed.");

//			// Claims to be included in the token
//			var claims = new[]
//			{
//				new Claim("userId", "Sam"),
//				new Claim(ClaimTypes.Role, "Developer"),
//				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
//				new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
//			};

//			// Create security keys for signing and encryption
//			var signingSecurityKey = new RsaSecurityKey(signingKey)
//			{
//				CryptoProviderFactory = new CryptoProviderFactory
//				{
//					CacheSignatureProviders = false // Avoid caching the signature providers
//				}
//			};

//			var encryptionSecurityKey = new RsaSecurityKey(encryptionKey)
//			{
//				CryptoProviderFactory = new CryptoProviderFactory
//				{
//					CacheSignatureProviders = false // Avoid caching the signature providers
//				}
//			};

//			// Generate AES key and IV for payload encryption
//			using (Aes aesAlg = Aes.Create())
//			{
//				aesAlg.KeySize = 128; // AES 128
//				aesAlg.GenerateKey();
//				aesAlg.GenerateIV();

//				// AES encrypting credentials (Payload encryption)
//				var encryptingCredentials = new EncryptingCredentials(
//					new RsaSecurityKey(encryptionKey),
//					SecurityAlgorithms.RsaOAEP,
//					SecurityAlgorithms.Aes128CbcHmacSha256
//				);

//				// Signing credentials (RSA-SHA256)
//				var signingCredentials = new SigningCredentials(
//					signingSecurityKey,
//					SecurityAlgorithms.RsaSha256
//				);

//				var tokenDescriptor = new SecurityTokenDescriptor
//				{
//					Issuer = "https://Sam",
//					Audience = "https://Speridian:5001",
//					Subject = new ClaimsIdentity(claims),
//					Expires = DateTime.UtcNow.AddMinutes(60),
//					SigningCredentials = signingCredentials,
//					EncryptingCredentials = encryptingCredentials
//				};

//				// Generate the encrypted JWT (JWE token)
//				string token = handler.CreateToken(tokenDescriptor);
//				return token;
//			}
//		}

//		// Method to load RSA keys from PEM files
//		private RSA LoadKey(string keyPath)
//		{
//			try
//			{
//				var keyText = File.ReadAllText(keyPath);
//				var key = RSA.Create();
//				key.ImportFromPem(keyText.ToCharArray()); // Import the PEM key
//				return key;
//			}
//			catch (Exception ex)
//			{
//				Console.WriteLine($"Error loading key from {keyPath}: {ex.Message}");
//				return null;
//			}
//		}

//		// Method to validate the generated token
//		public static bool ValidateToken(string token, string secretKey)
//		{
//			// Implement token validation logic here
//			return true; // Placeholder logic for now
//		}
//	}
//}
//using Microsoft.IdentityModel.JsonWebTokens;
//using Microsoft.IdentityModel.Tokens;
//using System;
//using System.Security.Claims;
//using System.Security.Cryptography;
//using System.IO;

//namespace JWE
//{
//	class Program
//	{
//		static void Main(string[] args)
//		{
//			TokenHelper tokenHelper = new TokenHelper();
//			Console.WriteLine("Generated Encrypted Token:");
//			Console.WriteLine(tokenHelper.GenerateToken());
//		}
//	}

//	public class TokenHelper
//	{
//		public string GenerateToken()
//		{
//			var handler = new JsonWebTokenHandler();

//			// Load RSA keys from PEM files
//			string privateKeyPath = "JWT/mykey.pem"; // Private key for signing
//			string publicKeyPath = "JWT/mypublickey.pem"; // Public key for encryption
//			var signingKey = LoadKey(privateKeyPath); // For signing
//			var encryptionKey = LoadKey(publicKeyPath); // For encryption

//			if (signingKey == null || encryptionKey == null)
//				throw new Exception("RSA key loading failed.");

//			// Claims to be included in the token
//			var claims = new[]
//			{
//				new Claim("userId", "Sam"),
//				new Claim(ClaimTypes.Role, "Developer"),
//				new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
//				new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
//			};

//			// Create security keys for signing and encryption
//			var signingSecurityKey = new RsaSecurityKey(signingKey)
//			{
//				CryptoProviderFactory = new CryptoProviderFactory
//				{
//					CacheSignatureProviders = false // Avoid caching the signature providers
//				}
//			};

//			var encryptionSecurityKey = new RsaSecurityKey(encryptionKey)
//			{
//				CryptoProviderFactory = new CryptoProviderFactory
//				{
//					CacheSignatureProviders = false // Avoid caching the signature providers
//				}
//			};

//			// Generate AES key and IV for payload encryption
//			using (Aes aesAlg = Aes.Create())
//			{
//				aesAlg.KeySize = 128; // AES 128
//				aesAlg.GenerateKey();
//				aesAlg.GenerateIV();

//				// AES encrypting credentials (Payload encryption)
//				var encryptingCredentials = new EncryptingCredentials(
//					new RsaSecurityKey(encryptionKey),
//					SecurityAlgorithms.RsaOAEP,
//					SecurityAlgorithms.Aes128CbcHmacSha256
//				);

//				// Signing credentials (RSA-SHA256)
//				var signingCredentials = new SigningCredentials(
//					signingSecurityKey,
//					SecurityAlgorithms.RsaSha256
//				);

//				var tokenDescriptor = new SecurityTokenDescriptor
//				{
//					Issuer = "https://Sam",
//					Audience = "https://Speridian:5001",
//					Subject = new ClaimsIdentity(claims),
//					Expires = DateTime.UtcNow.AddMinutes(60),
//					SigningCredentials = signingCredentials,
//					EncryptingCredentials = encryptingCredentials
//				};

//				// Generate the encrypted JWT (JWE token)
//				string token = handler.CreateToken(tokenDescriptor);
//				return token;
//			}
//		}

//		// Method to load RSA keys from PEM files
//		private RSA LoadKey(string keyPath)
//		{
//			try
//			{
//				var keyText = File.ReadAllText(keyPath);
//				var key = RSA.Create();
//				key.ImportFromPem(keyText.ToCharArray()); // Import the PEM key
//				return key;
//			}
//			catch (Exception ex)
//			{
//				Console.WriteLine($"Error loading key from {keyPath}: {ex.Message}");
//				return null;
//			}
//		}

//		// Method to validate the generated token
//		public static bool ValidateToken(string token, string secretKey)
//		{
//			// Implement token validation logic here
//			return true; // Placeholder logic for now
//		}
//	}
//}

//using Microsoft.IdentityModel.Tokens;
//using System;
//using System.Security.Claims;
//using System.Security.Cryptography;
//using System.IO;
//using System.IdentityModel.Tokens.Jwt;


//namespace JWE
//{
//	class Program
//	{
//		static void Main(string[] args)
//		{
//			TokenHelper tokenHelper = new TokenHelper();
//			Console.WriteLine("Generated Encrypted Token:");
//			Console.WriteLine(tokenHelper.GenerateToken());
//		}
//	}

//	public class TokenHelper
//	{
//		public string GenerateToken()
//		{
//			var handler = new JwtSecurityTokenHandler();

//			// Load RSA keys from PEM files
//			string privateKeyPath = "JWT/mykey.pem"; // Private key for signing
//			string publicKeyPath = "JWT/mypublickey.pem"; // Public key for encryption
//			var signingKey = LoadKey(privateKeyPath); // For signing
//			var encryptionKey = LoadKey(publicKeyPath); // For encryption

//			if (signingKey == null || encryptionKey == null)
//				throw new Exception("RSA key loading failed.");

//			// Claims to be included in the token
//			var claims = new[]
//			{
//		new Claim("userId", "Sam"),
//		new Claim(ClaimTypes.Role, "Developer"),
//		new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
//		new Claim(System.IdentityModel.Tokens.Jwt.JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64)
//		};

//			// Create security keys for signing
//			var signingSecurityKey = new RsaSecurityKey(signingKey)
//			{
//				CryptoProviderFactory = new CryptoProviderFactory
//				{
//					CacheSignatureProviders = false // Avoid caching the signature providers
//				}
//			};

//			// Generate AES key and IV for payload encryption
//			using var aesAlg = Aes.Create();
//			aesAlg.KeySize = 128; // AES 128
//			aesAlg.GenerateKey();
//			aesAlg.GenerateIV();

//			// AES encrypting credentials (Payload encryption)
//			var encryptingCredentials = new EncryptingCredentials(
//			new RsaSecurityKey(encryptionKey), // RSA Key for key wrapping
//			SecurityAlgorithms.RsaOAEP, // RSA-OAEP for key wrapping
//			SecurityAlgorithms.Aes128CbcHmacSha256 // Content encryption algorithm
//			);

//			// Signing credentials (RSA-SHA256)
//			var signingCredentials = new SigningCredentials(
//			signingSecurityKey,
//			SecurityAlgorithms.RsaSha256
//			);

//			var tokenDescriptor = new SecurityTokenDescriptor
//			{
//				Issuer = "https://Sam",
//				Audience = "https://Speridian:5001",
//				Subject = new ClaimsIdentity(claims),
//				Expires = DateTime.UtcNow.AddMinutes(60),
//				SigningCredentials = signingCredentials,
//				EncryptingCredentials = encryptingCredentials
//			};

//			// Generate the encrypted JWT (JWE token)
//			var token = handler.CreateToken(tokenDescriptor);
//			return handler.WriteToken(token);
//		}

//		// Method to load RSA keys from PEM files
//		private RSA LoadKey(string keyPath)
//		{
//			try
//			{
//				var keyText = File.ReadAllText(keyPath);
//				var key = RSA.Create();
//				key.ImportFromPem(keyText.ToCharArray()); // Import the PEM key
//				return key;
//			}
//			catch (Exception ex)
//			{
//				Console.WriteLine($"Error loading key from {keyPath}: {ex.Message}");
//				return null;
//			}
//		}

//		// Method to validate the generated token
//		public static bool ValidateToken(string token, string secretKey)
//		{
//			// Implement token validation logic here
//			return true; // Placeholder logic for now
//		}
//	}
//}

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