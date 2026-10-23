using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// JWT作成用の設定
var jwtSettings = builder.Configuration.GetSection("SelfJwt");
var jwtIssuer = jwtSettings["Issuer"] ?? throw new InvalidOperationException();
var jwtAudience = jwtSettings["Audience"] ?? throw new InvalidOperationException();
var jwtSecret = jwtSettings["SecretKey"] ?? throw new InvalidOperationException();
var jwtSecretBytes = Encoding.UTF8.GetBytes(jwtSecret);

// Add services to the container.
builder.Services.AddAuthentication()
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(jwtSecretBytes),

            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateIssuerSigningKey = true,

            ValidateLifetime = false,
        };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

// Configure the HTTP request pipeline.

app.UseAuthentication();
app.UseAuthorization();

app.Use(async (context, next) =>
{
    var endpoint = context.GetEndpoint();
    if (endpoint == null)
    {
        await next();
        return;
    }

    // 認証不要なエンドポイントはそのまま通す
    var authorizeData = endpoint.Metadata.GetMetadata<IAuthorizeData>();
    if (authorizeData == null)
    {
        await next();
        return;
    }

    // 「期限切れOK」の目印が付いているものは通す
    var allowExpired = endpoint.Metadata.GetMetadata<AllowExpiredMetadata>();
    if (allowExpired != null)
    {
        await next();
        return;
    }

    // 目印がなければ有効期限チェック
    var expClaim = context.User.FindFirst("exp")?.Value;
    if (expClaim != null && long.TryParse(expClaim, out var expUnix))
    {
        var expirationTime = DateTimeOffset.FromUnixTimeSeconds(expUnix);
        if (expirationTime > DateTimeOffset.UtcNow)
        {
            await next(); // 期限内なら進む
            return;
        }
    }

    // 期限切れの場合は 401 Unauthorized を返す
    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
    context.Response.ContentType = "application/json";
    await context.Response.WriteAsJsonAsync(new { message = "Token has expired." });
});


// 自前でやるよりIdPに任せるほうが良いようだが、ここでは自分でJWT発行する
app.MapPost("/login", (string user, string pass) =>
{

    // テキトウな認証
    if (user != "user" || pass != "password") return Results.Unauthorized();

    var tokenKey = new SymmetricSecurityKey(jwtSecretBytes);
    var tokenDescriptor = new SecurityTokenDescriptor
    {
        Subject = new ClaimsIdentity([
            new Claim(ClaimTypes.Name, user),
            new Claim(ClaimTypes.Role, "Admin"),
        ]),
        Expires = DateTime.UtcNow.AddSeconds(30),
        Issuer = jwtIssuer,
        Audience = jwtAudience,
        SigningCredentials = new SigningCredentials(tokenKey, SecurityAlgorithms.HmacSha256Signature)
    };
    var tokenHandler = new JwtSecurityTokenHandler();
    var token = tokenHandler.CreateToken(tokenDescriptor);
    var tokenString = tokenHandler.WriteToken(token);

    return Results.Ok(new { Token = tokenString });
});

app.MapGet("/strict-auth", () =>
{
    return new { Message = "Normal Authorization", };
}).RequireAuthorization();

app.MapGet("/allow-expire", () =>
{
    return new { Message = "Allow Expire", };
}).RequireAuthorization().WithMetadata(new AllowExpiredMetadata());

app.Run();

public class AllowExpiredMetadata;
