using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Session ve RazorPages için gerekli servisleri ekliyoruz
builder.Services.AddRazorPages();

// Session middleware yapýlandýrmasý
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(30);  // Session süresi
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// JWT ve authentication middleware'ini ekliyoruz
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
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
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["Jwt:SecretKey"]))
        };
    });

builder.Services.AddSingleton<IHttpContextAccessor, HttpContextAccessor>();


// API ile iletiþim kurmak için HttpClient servisini ekliyoruz
builder.Services.AddHttpClient("FruitAPI", httpClient =>
{
    httpClient.BaseAddress = new Uri("http://localhost:5050");  // API'nin base adresi
});

// Uygulama yapýlandýrmasý
var app = builder.Build();

// Session middleware'ini ekliyoruz
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();
app.UseSession();  // Session middleware'ini burada etkinleþtiriyoruz

// Razor Pages route yapýlandýrmasý
app.MapRazorPages();

app.Run();
