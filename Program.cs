using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;

var EndPoint = Environment.GetEnvironmentVariable("VAULT_ENDPOINT") ?? "https://localhost:8201";
Console.WriteLine($"VAULT_ENDPOINT: {EndPoint}");

var httpClientHandler = new HttpClientHandler();
httpClientHandler.ServerCertificateCustomValidationCallback =
    (message, cert, chain, sslPolicyErrors) => { return true; };

// Initialize one of the several auth methods.
IAuthMethodInfo authMethod =
    new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
// Initialize settings. You can also set proxies, custom delegates etc. here.
var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
{
    Namespace = "",
    MyHttpClientProviderFunc = handler
        => new HttpClient(httpClientHandler) {
            BaseAddress = new Uri(EndPoint)
        }
};
IVaultClient vaultClient = new VaultClient(vaultClientSettings);

string mySecret = string.Empty;
string myIssuer = string.Empty;

try
{
    Secret<SecretData> kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2
        .ReadSecretAsync(path: "passwords", mountPoint: "secret");
    mySecret = kv2Secret.Data.Data["Secret"].ToString();
    myIssuer = kv2Secret.Data.Data["Issuer"].ToString();
    Console.WriteLine($"Issuer er: {myIssuer}, og secret: {mySecret}");
}
catch (Exception e)
{
    Console.WriteLine("Noget gik galt her: " + e.Message);
}

if (string.IsNullOrEmpty(mySecret) || string.IsNullOrEmpty(myIssuer))
{
    throw new Exception("Secret or Issuer is not set correctly.");
}

var builder = WebApplication.CreateBuilder(args);

// Add the secrets to the configuration
builder.Configuration["Secret"] = mySecret;
builder.Configuration["Issuer"] = myIssuer;

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters()
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = myIssuer,
            ValidAudience = "http://localhost",
            IssuerSigningKey =
                new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret))
        };
    });

// Add services to the container.
builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

// Add HttpClient service
builder.Services.AddHttpClient();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();