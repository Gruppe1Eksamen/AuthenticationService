using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using NLog;
using NLog.Web;

// Setup NLog
var logger = LogManager
    .Setup()
    .LoadConfigurationFromAppSettings()
    .GetCurrentClassLogger();

logger.Debug("Init main");

try
{
    // Vault setup
    var endpoint = Environment.GetEnvironmentVariable("VAULT_ENDPOINT") ?? "https://localhost:8201";
    logger.Info($"VAULT_ENDPOINT: {endpoint}");

    var httpClientHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
    };

    IAuthMethodInfo authMethod = new TokenAuthMethodInfo("00000000-0000-0000-0000-000000000000");
    var vaultClientSettings = new VaultClientSettings(endpoint, authMethod)
    {
        MyHttpClientProviderFunc = handler => new HttpClient(httpClientHandler)
        {
            BaseAddress = new Uri(endpoint)
        }
    };
    IVaultClient vaultClient = new VaultClient(vaultClientSettings);

    Secret<SecretData> kv2Secret;
    try
    {
        kv2Secret = await ReadVaultSecretWithRetryAsync(
            vaultClient,
            path: "passwords",
            mountPoint: "secret",
            maxRetries: 5,
            delayBetweenRetries: TimeSpan.FromSeconds(5));
    }
    catch (Exception ex)
    {
        logger.Error(ex, "Failed to fetch secrets from Vault after 5 attempts");
        return;
    }

    var mySecret = kv2Secret.Data.Data["Secret"].ToString();
    var myIssuer = kv2Secret.Data.Data["Issuer"].ToString();
    logger.Info($"Vault Issuer: {myIssuer}");

    if (string.IsNullOrEmpty(mySecret) || string.IsNullOrEmpty(myIssuer))
    {
        throw new Exception("Secret or Issuer is not set correctly.");
    }

    // Web app setup
    var builder = WebApplication.CreateBuilder(args);

    builder.Logging.ClearProviders();
    builder.Logging.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Trace);
    builder.Host.UseNLog();

    builder.Configuration["Secret"] = mySecret;
    builder.Configuration["Issuer"] = myIssuer;

    builder.Services
        .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true,
                ValidIssuer = myIssuer,
                ValidAudience = "http://localhost",
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret))
            };
        });

    builder.Services.AddControllers();
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen();
    builder.Services.AddHttpClient();

    var app = builder.Build();

    app.UseSwagger();
    app.UseSwaggerUI();

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

// Vault retry helper
static async Task<Secret<SecretData>> ReadVaultSecretWithRetryAsync(
    IVaultClient vaultClient,
    string path,
    string mountPoint,
    int maxRetries = 5,
    TimeSpan? delayBetweenRetries = null)
{
    delayBetweenRetries ??= TimeSpan.FromSeconds(5);

    for (int attempt = 1; attempt <= maxRetries; attempt++)
    {
        try
        {
            return await vaultClient.V1.Secrets.KeyValue.V2
                .ReadSecretAsync(path: path, mountPoint: mountPoint);
        }
        catch (Exception ex) when (attempt < maxRetries)
        {
            Console.WriteLine(
                $"[Vault] Attempt {attempt} failed: {ex.Message}. Retrying in {delayBetweenRetries.Value.TotalSeconds}s...");
            await Task.Delay(delayBetweenRetries.Value);
        }
    }

    throw new Exception($"Failed to read secret from Vault after {maxRetries} attempts.");
}
