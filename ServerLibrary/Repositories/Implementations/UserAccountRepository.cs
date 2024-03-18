using BaseLibrary.Dtos;
using BaseLibrary.Entities;
using BaseLibrary.Responses;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.VisualBasic;
using ServerLibrary.Data;
using ServerLibrary.Helpers;
using ServerLibrary.Repositories.Contracts;
using System;
using System.Buffers.Text;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Constants = ServerLibrary.Helpers.Constants;

namespace ServerLibrary.Repositories.Implementations
{
	public class UserAccountRepository : IUserAccount
	{
        public UserAccountRepository(IOptions<JwtSection> config, AppDbContext appDbContext)
        {
			Config = config;
			AppDbContext = appDbContext;
		}

		public IOptions<JwtSection> Config { get; }
		public AppDbContext AppDbContext { get; }

		//Create
		public async Task<GeneralResponse> CreateAsync(Register user)
		{
			if (user is null) return new GeneralResponse(false, "Model is empty");

			var checkUser = await FindUserByEmail(user.Email!);
			if (checkUser != null) return new GeneralResponse(false, "User registered already");

			//save user
			var applicationUser = await AddToDatabase(new ApplicationUser()
			{
				FullName = user.FullName,
				Email = user.Email,
				Password = BCrypt.Net.BCrypt.HashPassword(user.Password)
			});

			//check, creating and assign role.
			//The first person register will be admin, and the rest will be user
			var checkAdminRole = await AppDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.Admin));

			if(checkAdminRole is null)
			{
				//Just Once
				var createAdminRole = await AddToDatabase(new SystemRole() { Name = Constants.Admin });
				await AddToDatabase(new UserRole() { RoleId = createAdminRole.Id, UserId = applicationUser.Id});
				return new GeneralResponse(true, "Account created");
			}

			var checkUserRole = await AppDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Name!.Equals(Constants.User));
			SystemRole response = new();
			if(checkUserRole is null)
			{
				//Just Once
				response = await AddToDatabase(new SystemRole() { Name = Constants.User });
				await AddToDatabase(new UserRole() { RoleId = response.Id, UserId = applicationUser.Id });
			}
			else
			{
				//After 2 time
				await AddToDatabase(new UserRole() { RoleId = checkUserRole.Id, UserId = applicationUser.Id });
			}
			return new GeneralResponse(true, "Account created");
		}
		private async Task<ApplicationUser> FindUserByEmail(string email) =>
			await AppDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Email!.ToLower()!.Equals(email!.ToLower()));

		private async Task<T> AddToDatabase<T>(T model)
		{
			var result = AppDbContext.Add(model!);
			await AppDbContext.SaveChangesAsync();
			return (T)result.Entity;
		}

		//SignIn
		public async Task<LoginResponse> SignInAsync(Login user)
		{
			if (user is null) return new LoginResponse(false, "Model is empty");

			var applicationUser = await FindUserByEmail(user.Email!);
			if (applicationUser is null) return new LoginResponse(false, "User not found");

			//Verify Password
			if (!BCrypt.Net.BCrypt.Verify(user.Password, applicationUser.Password))
			return new LoginResponse(false, "Email/Password not valid");

			var getUserRole = await FindUserRole(applicationUser.Id);
			if (getUserRole is null) return new LoginResponse(false, "User role not found");

			var getRoleName = await FindRoleName(getUserRole.RoleId);
			if (getRoleName is null) return new LoginResponse(false, "User role name not found");

			string jwtToken = GenerateToken(applicationUser, getRoleName!.Name!);
			string refreshToken = GenerateRefreshToken();

			//Refresh  token saving or updating
			var findUser = await AppDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == applicationUser.Id);
			if(findUser is not null)
			{
				findUser!.Token = refreshToken;
				await AppDbContext.SaveChangesAsync();
			}
			else
			{
				await AddToDatabase(new RefreshTokenInfo() { Token = refreshToken, UserId = applicationUser.Id });
			}
			return new LoginResponse(true, "Login successfully", jwtToken, refreshToken);
		}

		/* SymmetricSecurityKey:
		 * Es una clase en .NET que representa una clave simétrica, lo que significa que la misma clave se utiliza tanto para 
		 cifrar como para descifrar datos.
		 * En el contexto de este código, la clave secreta obtenida desde la configuración se convierte en un objeto de tipo 
		 SymmetricSecurityKey. Esta clave se utilizará para generar la firma HMAC-SHA256 para el token JWT.
		
		 SigningCredentials:
		 * Es una clase que encapsula la información necesaria para firmar un token JWT.
		 * La función principal de SigningCredentials es proporcionar las credenciales necesarias (en este caso, la clave simétrica y 
		  el algoritmo de firma) para firmar el token JWT.
		 * En este código, se crea una instancia de SigningCredentials utilizando la clave simétrica (SymmetricSecurityKey) y 
		  el algoritmo de firma (HMAC-SHA256).
		Firma HMAC-SHA256:

		HMAC (Hash-based Message Authentication Code) es un algoritmo que utiliza una función de hash criptográfica (como SHA-256)
		junto con una clave secreta para generar una firma digital única para un conjunto de datos.
		 
		Estos claims son declaraciones sobre el sujeto, y pueden representar atributos como su identidad, roles, permisos, etc.
		Estos claims se empaquetarán dentro del token JWT y se utilizarán para proporcionar información sobre la identidad
		y los privilegios del usuario.
		 */
		private string GenerateToken(ApplicationUser user, string role)
		{
			var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Config.Value.Key!));
			var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

			var userClaims = new[]
			{
				new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
				new Claim(ClaimTypes.Name, user.FullName!),
				new Claim(ClaimTypes.Email, user.Email!),
				new Claim(ClaimTypes.Role, role!)
			};
			var token = new JwtSecurityToken(
				issuer: Config.Value.Issuer,
				audience: Config.Value.Audience,
				claims: userClaims,
				expires: DateTime.Now.AddDays(1),
				signingCredentials: credentials
				);
			return new JwtSecurityTokenHandler().WriteToken(token);
		}

		/*1. RandomNumberGenerator.GetBytes(64): Se utiliza RandomNumberGenerator para generar una secuencia de bytes aleatoria de longitud 64.
		Esto proporciona una cadena de bytes aleatoria y segura que será utilizada como el token de actualización.
		
		2. Convert.ToBase64String: Luego, la secuencia de bytes aleatoria se convierte a una cadena Base64.La conversión a Base64
		la hace más legible y fácil de almacenar o transmitir.*/
		private static string GenerateRefreshToken() => Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

		private async Task<UserRole> FindUserRole(int userId) => await AppDbContext.UserRoles.FirstOrDefaultAsync(_ => _.UserId == userId);
		private async Task<SystemRole> FindRoleName(int roleId) => await AppDbContext.SystemRoles.FirstOrDefaultAsync(_ => _.Id == roleId);

		public async Task<LoginResponse> RefreshTokenAsync(RefreshToken token)
		{
			if (token is null) return new LoginResponse(false, "Model is empty");
			 
			var findToken = await AppDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.Token!.Equals(token.Token));
			if (findToken is null) return new LoginResponse(false, "Valid refresh token is required");

			//Get user detailts
			var user = await AppDbContext.ApplicationUsers.FirstOrDefaultAsync(_ => _.Id == findToken.UserId);
			if (user is null) return new LoginResponse(false, "Refresh token could not be generated user not found");

			var userRole = await FindUserRole(user.Id);
			var roleName = await FindRoleName(userRole.RoleId);
			string jwtToken = GenerateToken(user, roleName.Name!);
			string refreshToken = GenerateRefreshToken();

			//Ojo, se actualiza el Rsh token del usuario
			var updateRefreshToken = await AppDbContext.RefreshTokenInfos.FirstOrDefaultAsync(_ => _.UserId == user.Id);
			if (updateRefreshToken is null) return new LoginResponse(false, "Refresh token could not be genered because user has not signed in");

			updateRefreshToken.Token = refreshToken;
			await AppDbContext.SaveChangesAsync();
			return new LoginResponse(true, "Token refreshed successfully", jwtToken, refreshToken);
		}
	}
}
