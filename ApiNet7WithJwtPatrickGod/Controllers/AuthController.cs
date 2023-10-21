using ApiNet7WithJwtPatrickGod.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace ApiNet7WithJwtPatrickGod.Controllers
{
  [Route("api/[controller]")]
  [ApiController]
  public class AuthController : ControllerBase
  {
    public static User user = new User();
    private readonly IConfiguration _configuration;

    public AuthController(IConfiguration configuration)
    {
      _configuration = configuration;
    }

    [HttpPost]
    [Route("Register")]
    public ActionResult<User> Register(UserDto userDto)
    {
      string passwordHash = BCrypt.Net.BCrypt.HashPassword(userDto.Password);

      user.UserName = userDto.UserName;
      user.PasswordHash = passwordHash;

      return Ok(user);
    }

    [HttpPost]
    [Route("Login")]
    public ActionResult<User> Login(UserDto userDto)
    {
      if (user.UserName != userDto.UserName) return BadRequest("Usuario no encontrado");

      if (!BCrypt.Net.BCrypt.Verify(userDto.Password, user.PasswordHash)) return BadRequest("Contraseña incorrecta");

      string token = CreateToken(user);

      return Ok(token);
    }

    private string CreateToken(User user)
    {
      List<Claim> claims = new List<Claim>()
      {
        new Claim(ClaimTypes.Name, user.UserName),
        new Claim(ClaimTypes.Role, "ADMIN"),
        new Claim(ClaimTypes.Role, "USER"),
      };

      var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.GetSection("JwtSettings:Key").Value!));

      var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

      var token = new JwtSecurityToken(
        claims: claims,
        expires: DateTime.UtcNow.AddDays(1),
        signingCredentials: credentials
      );

      var jwt = new JwtSecurityTokenHandler().WriteToken(token);

      return jwt;
    }
  }
}
