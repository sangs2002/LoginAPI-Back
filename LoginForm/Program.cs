using LoginForm.Context;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using static LoginForm.Controllers.UserController;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

#region DataBase

var connnection = builder.Configuration.GetConnectionString("DefaultConnection");

builder.Services.AddDbContext<UserDBConetext>(options => options.UseSqlServer(connnection));
#endregion


#region Cors

builder.Services.AddCors(options => options.AddPolicy("CustomPolicy", builder => builder.AllowAnyHeader().AllowAnyMethod().AllowAnyOrigin()));

#endregion

#region Authentication

builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(x =>
{
    x.RequireHttpsMetadata = false;
    x.SaveToken = true;
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        // Generate a new key with 128 bits length
        IssuerSigningKey = new SymmetricSecurityKey(KeyGenerator.GenerateKey(256)),
        ValidateAudience = false,
        ValidateIssuer = false,
        ClockSkew=TimeSpan.Zero
    };
});


#endregion




builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseCors("CustomPolicy");

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.Run();
