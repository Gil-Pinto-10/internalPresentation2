using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace vulnerableService
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            var key = "This is my super secret key for JWT";

            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        ValidateLifetime = true,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key))
                    };
                });

            builder.Services.AddAuthorization();

            builder.Services.AddEndpointsApiExplorer();
            builder.Services.AddSwaggerGen();
            
            builder.Services.AddSwaggerGen(options =>
            {
                options.SwaggerDoc("v1", new() { Title = "Vulnerable API", Version = "v1" });

                // 🔐 Add JWT Bearer definition
                options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                {
                    Description = "JWT Authorization header using the Bearer scheme.\n\nEnter: **Bearer {your_token}**",
                    Name = "Authorization",
                    In = Microsoft.OpenApi.Models.ParameterLocation.Header,
                    Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
                    Scheme = "Bearer"
                });

                // 🔐 Add global security requirement
                options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement
                {
                    {
                        new Microsoft.OpenApi.Models.OpenApiSecurityScheme
                        {
                            Reference = new Microsoft.OpenApi.Models.OpenApiReference
                            {
                                Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                                Id = "Bearer"
                            }
                        },
                        Array.Empty<string>()
                    }
                });
            });

            
            var app = builder.Build();

            app.UseSwagger();
            app.UseSwaggerUI();

            
            app.UseAuthentication();
            app.UseAuthorization();

            // In-memory user store
            var users = new List<User>();

            app.MapPost("/register", (RegisterRequest request) =>
            {
                if (users.Any(u => u.Email == request.Email))
                    return Results.BadRequest("Email already exists");

                var newUser = new User(users.Count + 1, request.Email, request.Password, request.CardNumber);
                users.Add(newUser);
                return Results.Ok("User registered!");
            });

            app.MapPost("/login", (LoginRequest request) =>
            {
                var user = users.FirstOrDefault(u => u.Email == request.Email && u.Password == request.Password);
                if (user == null)
                    return Results.Unauthorized();

                var claims = new[]
                {
                    new Claim("userId", user.Id.ToString()),
                    new Claim("email", user.Email)
                };

                var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddHours(1),
                    signingCredentials: new SigningCredentials(
                        new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key)),
                        SecurityAlgorithms.HmacSha256)
                );

                var tokenString = new JwtSecurityTokenHandler().WriteToken(token);
                return Results.Ok(new { token = tokenString });
            });

            app.MapGet("/me", (ClaimsPrincipal userPrincipal) =>
            {
                var userIdClaim = userPrincipal.FindFirst("userId");
                if (userIdClaim == null)
                    return Results.Unauthorized();

                var userId = int.Parse(userIdClaim.Value);
                var user = users.FirstOrDefault(u => u.Id == userId);
                if (user == null)
                    return Results.NotFound();

                return Results.Ok(new { user.Id, user.Email, user.CardNumber });
            }).RequireAuthorization();
            
            // 🚨 VULNERABLE: uses user-provided ID even though the user is authenticated
            app.MapPost("/me/details", (HttpContext http, UserIdRequest req) =>
            {
                // 🚨 BAD: ignores authenticated user's identity, trusts client input
                var user = users.FirstOrDefault(u => u.Id == req.Id);
                if (user == null)
                    return Results.NotFound();

                return Results.Ok(new
                {
                    user.Id,
                    user.Email,
                    user.CardNumber
                });
            }).RequireAuthorization();

            app.Run();
        }
    }

    public record User(int Id, string Email, string Password, string CardNumber);
    public record RegisterRequest(string Email, string Password, string CardNumber);
    public record LoginRequest(string Email, string Password);
    
    public record UserIdRequest(int Id);
}
