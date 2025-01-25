using Microsoft.AspNetCore.Mvc;
using Novell.Directory.Ldap;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using FruitAPI;
using Microsoft.IdentityModel.Tokens;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory.Database;

[ApiController]
[Route("api/[controller]")]
public class LoginController : ControllerBase
{
    private readonly IConfiguration _configuration;

    public LoginController(IConfiguration configuration)
    {
        _configuration = configuration;
    }
}
