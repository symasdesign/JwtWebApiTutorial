using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace JwtWebApiTutorial.Controllers {
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase {
        public static User user = new User();
        private readonly IConfiguration configuration;

        public AuthController(IConfiguration configuration) {
            this.configuration = configuration;
        }

        [HttpPost("register")] // Post with a Router
        public async Task<ActionResult<User>> Register(UserDto request) {
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto request) {
            if (user.Username != request.Username) {
                return BadRequest("User not found.");
            }

            if(!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt)) {
                return BadRequest("Wrong password.");
            }

            var token = CreateToken(user);
            //return Ok("MY CRAZY TOKEN");

            // token can be decoded at jwt.io
            // or here for testing
            var tokenInfo = GetTokenInfo(token);

            return Ok(token);
        }

        private Dictionary<string, string> GetTokenInfo(string token) {
            var TokenInfo = new Dictionary<string, string>();

            var handler = new JwtSecurityTokenHandler();
            var jwtSecurityToken = handler.ReadJwtToken(token);
            var claims = jwtSecurityToken.Claims.ToList();

            foreach (var claim in claims) {
                TokenInfo.Add(claim.Type, claim.Value);
            }

            return TokenInfo;
        }

        private string CreateToken(User user) {
            var claims = new List<Claim>(); // Claim describes the user, there can be any data, Roles for example
            claims.Add(new Claim(ClaimTypes.Name, user.Username));
            var token = System.Text.Encoding.UTF8.GetBytes(configuration.GetSection("AppSettings:Token").Value);
            var key = new SymmetricSecurityKey(token);  // Package Microsoft.IdentityModel.Tokens

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            // Package System.IdentityModel.Tokens.Jwt
            var jwtToken = new JwtSecurityToken(claims: claims, expires: DateTime.Now.AddDays(1), signingCredentials: creds);

            var jwt = new JwtSecurityTokenHandler().WriteToken(jwtToken);

            return jwt;
        }

        private void CreatePasswordHash(string plainPassword, out byte[] passwordHash, out byte[] passwordSalt) {
            using (var hmac = new HMACSHA512()) {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(plainPassword));
            }
        }

        private bool VerifyPasswordHash(string plainPassword, byte[] passwordHash, byte[] passwordSalt) {
            using(var hmac = new HMACSHA512(passwordSalt)) {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(plainPassword));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}
