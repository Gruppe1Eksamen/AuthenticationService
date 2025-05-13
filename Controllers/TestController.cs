using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Mvc;

namespace AuthService.Controllers
{
    [ApiController]
    [Route("api/secure")]
    public class SecureController : ControllerBase
    {
        [Authorize]// Kræver authentication
        [HttpGet("data")]
        public async Task<IActionResult> Get()
        {
            return Ok("You're authorized");
        }
    }
}