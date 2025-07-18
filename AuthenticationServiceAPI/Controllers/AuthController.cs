using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using System.Net.Http;
using System.Net.Http.Json;
using System.Threading.Tasks;
using System.Diagnostics;
using AuthService.Models;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/auth")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly ILogger<AuthController> _logger;
        private readonly HttpClient _httpClient;
        private readonly string _userServiceBase;

        public AuthController(ILogger<AuthController> logger, IConfiguration config, HttpClient httpClient)
        {
            _config = config;
            _logger = logger;
            _httpClient = httpClient;
            _userServiceBase = _config["USERSERVICE_ENDPOINT"] ?? "http://localhost:5077";
        }

        [AllowAnonymous]
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel login)
        {
            var validateUrl = $"{_userServiceBase}/api/users/validatecredentials";

            _logger.LogInformation("Kalder UserService på {Url}", validateUrl);
            var response = await _httpClient.PostAsJsonAsync(validateUrl, login);
            if (response.IsSuccessStatusCode)
            {
                var isValidUser = await response.Content.ReadFromJsonAsync<bool>();
                if (isValidUser)
                {
                    var token = GenerateJwtToken(login.Username);
                    return Ok(new 
                    { 
                        message = "Authorized for 60 minutes",
                        token, 
                    });                
                }
            }

            return Unauthorized();
        }


        private string GenerateJwtToken(string username)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Secret"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username)
            };

            var token = new JwtSecurityToken(
                _config["Issuer"],
                "http://localhost",
                claims,
                expires: DateTime.UtcNow.AddMinutes(60),
                signingCredentials: credentials
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
        
        [AllowAnonymous]
        [HttpGet("version")]
        public async Task<Dictionary<string,string>> GetVersion()
        {
            var properties = new Dictionary<string, string>();
            var assembly = typeof(Program).Assembly;
            properties.Add("service", "AuthService");
            var ver = FileVersionInfo.GetVersionInfo(typeof(Program)
                .Assembly.Location).ProductVersion;
            properties.Add("version", ver!);
            try {
                var hostName = System.Net.Dns.GetHostName();
                var ips = await System.Net.Dns.GetHostAddressesAsync(hostName);
                var ipa = ips.First().MapToIPv4().ToString();
                properties.Add("hosted-at-address", ipa);
            } catch (Exception ex) {
                _logger.LogError(ex.Message);
                properties.Add("hosted-at-address", "Could not resolve IP-address");
            }
            return properties;
        }
        
        [Authorize]
        [HttpGet("authcheck")]
        public async Task<IActionResult> Get()
        {
            return Ok("You're authorized");
        }
    }


}