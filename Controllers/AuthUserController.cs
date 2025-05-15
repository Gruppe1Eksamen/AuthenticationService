using AuthService.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/user")]
    public class AuthUserController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly ILogger<AuthController> _logger;
        private readonly HttpClient _httpClient;
        private readonly string _userServiceBase;

        public AuthUserController(ILogger<AuthController> logger, IConfiguration config, HttpClient httpClient)
        {
            _config = config;
            _logger = logger;
            _httpClient = httpClient;
            _userServiceBase = _config["USERSERVICE_ENDPOINT"] ?? "http://localhost:5077";
        }
        
        [Authorize]
        [HttpPost]
        public async Task<ActionResult<User>> CreateUser([FromBody] User user)
        {
            var url = $"{_userServiceBase}/user";
            _logger.LogInformation("Creating user via UserService at {Url}", url);

            try
            {
                var response = await _httpClient.PostAsJsonAsync(url, user);
                if (response.IsSuccessStatusCode)
                {
                    var createdUser = await response.Content.ReadFromJsonAsync<User>();
                    return CreatedAtRoute("GetUserById", new { userId = createdUser.Id }, createdUser);
                }
                return StatusCode((int)response.StatusCode, "Failed to create user");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while creating user");
                return StatusCode(500, "Internal server error");
            }
        }
        
        [Authorize]
        [HttpGet("{userId}", Name = "GetUserById")]
        public async Task<ActionResult<User>> GetUserById(string userId)
        {
            var url = $"{_userServiceBase}/user/{userId}";
            _logger.LogInformation("Fetching user by ID via UserService at {Url}", url);

            try
            {
                var response = await _httpClient.GetAsync(url);
                if (response.IsSuccessStatusCode)
                {
                    var user = await response.Content.ReadFromJsonAsync<User>();
                    return Ok(user);
                }
                return StatusCode((int)response.StatusCode, "Failed to fetch user");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while fetching user by ID");
                return StatusCode(500, "Internal server error");
            }
        }
        
        [Authorize]
        [HttpGet]
        public async Task<ActionResult<IEnumerable<User>>> GetAllUsers()
        {
            var url = $"{_userServiceBase}/user";
            _logger.LogInformation("Fetching all users via UserService at {Url}", url);

            try
            {
                var response = await _httpClient.GetAsync(url);
                if (response.IsSuccessStatusCode)
                {
                    var users = await response.Content.ReadFromJsonAsync<List<User>>();
                    return Ok(users);
                }
                return StatusCode((int)response.StatusCode, "Failed to fetch users");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while fetching all users");
                return StatusCode(500, "Internal server error");
            }
        }
        
        [Authorize]
        [HttpPut("{userId}")]
        public async Task<ActionResult<User>> UpdateUser(string userId, [FromBody] User updatedUser)
        {
            var url = $"{_userServiceBase}/user/{userId}";
            _logger.LogInformation("Updating user via UserService at {Url}", url);

            try
            {
                var response = await _httpClient.PutAsJsonAsync(url, updatedUser);
                if (response.IsSuccessStatusCode)
                {
                    var user = await response.Content.ReadFromJsonAsync<User>();
                    return Ok(user);
                }
                return StatusCode((int)response.StatusCode, "Failed to update user");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while updating user");
                return StatusCode(500, "Internal server error");
            }
        }

        [Authorize]
        [HttpDelete("{userId}")]
        public async Task<ActionResult> DeleteUser(string userId)
        {
            var url = $"{_userServiceBase}/user/{userId}";
            _logger.LogInformation("Deleting user via UserService at {Url}", url);

            try
            {
                var response = await _httpClient.DeleteAsync(url);
                if (response.IsSuccessStatusCode)
                {
                    return NoContent();
                }
                return StatusCode((int)response.StatusCode, "Failed to delete user");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error while deleting user");
                return StatusCode(500, "Internal server error");
            }
        }
    }
}