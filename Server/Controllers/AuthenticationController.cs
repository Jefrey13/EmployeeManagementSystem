using BaseLibrary.Dtos;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using ServerLibrary.Repositories.Contracts;

namespace Server.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthenticationController : ControllerBase
	{
        public AuthenticationController(IUserAccount accountInterface)
        {
			AccountInterface = accountInterface;
		}

		public IUserAccount AccountInterface { get; }

		[HttpPost("register")]
		public async Task<IActionResult> CreateAsync(Register user)
		{
			if (user == null) return BadRequest("Model is empty");
			var result = await AccountInterface.CreateAsync(user);
			return Ok(result);
		}

		[HttpPost("login")]
		public async Task<IActionResult> SignInAsync(Login user)
		{
			if (user is null) return BadRequest("Model is empty");
			var result = await AccountInterface.SignInAsync(user);
			return Ok(result);
		}
		[HttpPost("refresh-token")]
		public async Task<IActionResult> RefreshTokenAsync(RefreshToken token)
		{
			if (token == null) return BadRequest("Model is empty");
			var result = await AccountInterface.RefreshTokenAsync(token);
			return Ok(result);
		}
	}
}
