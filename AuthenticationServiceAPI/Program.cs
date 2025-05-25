using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using NLog;
using NLog.Web;

var logger = NLogBuilder.ConfigureNLog("NLog.config").GetCurrentClassLogger();

try
{
    logger.Debug("Starting application");

    var EndPoint = Environment.GetEnvironmentVariable("VAULT_ENDPOINT") ?? "https://localhost:8201";
    logger.Info($"VAULT_ENDPOINT: {EndPoint}");

    var httpClientHandler = new HttpClientHandler();
    httpClientHandler.ServerCertificateCustomValidationCallback =
        (message, cert, chain, sslPolicyErrors) => true;

    IAuthMethodInfo authMethod =
        new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");

    var vaultClientSettings = new VaultClientSettings(EndPoint, authMethod)
    {
        Namespace = "",
        MyHttpClientProviderFunc = handler =>
            new HttpClient(httpClientHandler) { BaseAddress = new Uri(EndPoint) }
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
        logger.Info($"Issuer: {myIssuer}, Secret fetched");
    }
    catch (Exception e)
    {
        logger.Error(e, "Failed to read secrets from Vault");
        throw;
    }

    if (string.IsNullOrEmpty(mySecret) || string.IsNullOrEmpty(myIssuer))
    {
        throw new Exception("Secret or Issuer is not set correctly.");
    }

    var builder = WebApplication.CreateBuilder(args);

    // Setup NLog for Dependency Injection logging
    builder.Logging.ClearProviders();
    builder.Logging.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Trace);
    builder.Host.UseNLog();

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
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();

    // Add HttpClient service
    builder.Services.AddHttpClient();

    var app = builder.Build();

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseAuthentication();
    app.UseAuthorization();

    app.MapControllers();

    app.Run();
}
catch (Exception ex)
{
    logger.Error(ex, "Application stopped due to exception");
    throw;
}
finally
{
    LogManager.Shutdown();
}
