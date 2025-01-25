using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.DirectoryServices.Protocols;  // New LDAP library
using FruitAPI;
using System.Net;
using static Microsoft.EntityFrameworkCore.DbLoggerCategory.Database;
//using Novell.Directory.Ldap;

var builder = WebApplication.CreateBuilder(args);

// JWT Authentication için handler'ý entegre et
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddScheme<AuthenticationSchemeOptions, LdapAuthenticationHandler>("LDAP", options => { })
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"],
        ValidAudience = builder.Configuration["Jwt:Audience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"])),
        RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"


    };
});

// Database ve CRUD iþlemleri için Entity Framework yapýlandýrmasý
builder.Services.AddDbContext<FruitDb>(opt => opt.UseInMemoryDatabase("FruitList"));
builder.Services.AddDatabaseDeveloperPageExceptionFilter();
builder.Services.AddEndpointsApiExplorer();

// Swagger için güvenlik ve yapýlandýrma
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo
    {
        Version = "v1",
        Title = "Fruit API",
        Description = "API for managing a list of fruit and their stock status.",
    });

    // JWT Authentication için Swagger'a güvenlik tanýmý ekleyin
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        In = ParameterLocation.Header,
        Description = "Please insert JWT token into field (Bearer {token})",
        Name = "Authorization",
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    // JWT token gerektiren endpoint'ler için Swagger güvenlik gereksinimini ekleyin
    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = ParameterLocation.Header
            },
            new string[] { }
        }
    });
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", policy => policy.RequireRole("Admin"));
    options.AddPolicy("Manav", policy => policy.RequireRole("Manav"));
    options.AddPolicy("Halci", policy => policy.RequireRole("Halci"));
});

builder.Services.AddLogging(config =>
{
    config.AddConsole();  // Konsola log yazma
    config.SetMinimumLevel(LogLevel.Trace);
});

builder.Services.AddScoped<IJwtTokenService, JwtTokenService>();

var app = builder.Build();

// Veritabaný oluþturuluyor
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    var dbContext = services.GetRequiredService<FruitDb>();
    dbContext.Database.EnsureCreated();
}

// Login için POST route ekliyoruz
app.MapPost("/login", (LoginModel model) =>
{
    string ldapServer = "127.0.0.1";
    int ldapPort = 10389;
    string baseDn = "ou=users,ou=system";

    // LDAP doðrulama ve gruplarý alma
    var roles = new List<string>();
    if (AuthenticateWithLdapAndRetrieveGroups(model.Username, model.Password, ldapServer, ldapPort, baseDn, out roles))
    {
        // Kullanýcý doðrulandýktan sonra JWT token oluþtur
        var token = GenerateJwtToken(model.Username, builder.Configuration["Jwt:SecretKey"], builder.Configuration["Jwt:Issuer"], builder.Configuration["Jwt:Audience"], roles);

        return Results.Ok(new { token });
    }

    return Results.Problem("Invalid credentials");
});

bool AuthenticateWithLdapAndRetrieveGroups(string username, string password, string ldapServer, int ldapPort, string baseDn, out List<string> roles)
{
    roles = new List<string>();
    try
    {
        var ldapConnection = new LdapConnection($"{ldapServer}:{ldapPort}");
        var networkCredential = new NetworkCredential("uid=admin,ou=system","secret");
        ldapConnection.SessionOptions.ProtocolVersion = 3;
        ldapConnection.AuthType = AuthType.Basic;
        ldapConnection.Bind(networkCredential);

        // Kullanýcýnýn gruplarýný al
        string ara = $"cn={username},{baseDn}";
        var filter = $"(&(objectClass=groupOfUniqueNames)(uniqueMember={ara}))";
        var searchRequest = new SearchRequest("ou=groups,ou=system", filter, SearchScope.Subtree, "cn");
        var searchResponse = (SearchResponse)ldapConnection.SendRequest(searchRequest);

        foreach (SearchResultEntry entry in searchResponse.Entries)
        {
            var groupName = entry.Attributes["cn"]?[0].ToString();
            if (!string.IsNullOrEmpty(groupName))
            {
                roles.Add(groupName);
            }
        }
        ldapConnection?.Dispose();
        return true;
    }
    catch
    {
        return false;
    }   
}

string GenerateJwtToken(string username, string secretKey, string issuer, string audience, List<string> roles)
{
    var claims = new List<Claim>
    {
        new Claim(ClaimTypes.Name, username)
    };

    // Kullanýcýnýn LDAP gruplarýný JWT'ye ekleyin
    foreach (var role in roles)
    {
        claims.Add(new Claim(ClaimTypes.Role, role));
    }

    var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));
    var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken(
        issuer: issuer,
        audience: audience,
        claims: claims,
        expires: DateTime.Now.AddDays(1),
        signingCredentials: creds
    );

    return new JwtSecurityTokenHandler().WriteToken(token);
}


// CRUD API routes
app.MapGet("/fruitlist", async (FruitDb db) => await db.Fruits.ToListAsync())
    .WithTags("Get all fruit");

app.MapGet("/fruitlist/instock", async (FruitDb db) => await db.Fruits.Where(t => t.Instock).ToListAsync())
    .WithTags("Get all fruit that is in stock")
    .RequireAuthorization("Manav");

app.MapGet("/fruitlist/{id}", async (int id, FruitDb db) =>
{
    return await db.Fruits.FindAsync(id) is Fruit fruit ? Results.Ok(fruit) : Results.NotFound();
})
.WithTags("Get fruit by Id")
.RequireAuthorization("Manav");

app.MapPost("/fruitlist", async (Fruit fruit, FruitDb db) =>
{
    db.Fruits.Add(fruit);
    await db.SaveChangesAsync();
    return Results.Created($"/fruitlist/{fruit.Id}", fruit);
})
.WithTags("Add fruit to list");

app.MapPut("/fruitlist/{id}", async (int id, Fruit inputFruit, FruitDb db) =>
{
    var fruit = await db.Fruits.FindAsync(id);
    if (fruit is null) return Results.NotFound();

    fruit.Name = inputFruit.Name;
    fruit.Instock = inputFruit.Instock;
    await db.SaveChangesAsync();
    return Results.NoContent();
})
.WithTags("Update fruit by Id")
.RequireAuthorization("Admin", "Halci");

app.MapDelete("/fruitlist/{id}", async (int id, FruitDb db) =>
{
    var fruit = await db.Fruits.FindAsync(id);
    if (fruit is null) return Results.NotFound();

    db.Fruits.Remove(fruit);
    await db.SaveChangesAsync();
    return Results.Ok(fruit);
})
.WithTags("Delete fruit by Id")
.RequireAuthorization("Admin", "Halci");

// Swagger ve UI
app.UseSwagger();
app.UseSwaggerUI();

// Kimlik doðrulama ve yetkilendirme
app.UseAuthentication();
app.UseAuthorization();

app.Run();
