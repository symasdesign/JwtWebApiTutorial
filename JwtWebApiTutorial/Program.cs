using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Swashbuckle.AspNetCore.Filters;

namespace JwtWebApiTutorial {
    public class Program {
        public static void Main(string[] args) {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.

            builder.Services.AddControllers();
            // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
            builder.Services.AddEndpointsApiExplorer();

            //builder.Services.AddSwaggerGen();
            // --- add Authorization-Button to Swagger
            // https://mattfrear.com/2018/07/21/add-an-authorization-header-to-your-swagger-ui-with-swashbuckle-revisited/
            builder.Services.AddSwaggerGen(options => {
                options.AddSecurityDefinition("oauth2", new OpenApiSecurityScheme {
                    Description = "Standard Authorization header using the Bearer scheme (\"bearer {token}\")",
                    In = ParameterLocation.Header,
                    Name = "Authorization",
                    Type = SecuritySchemeType.ApiKey
                });
                options.OperationFilter<SecurityRequirementsOperationFilter>(); // 
            });
            
            // ---


            // --- Package: Microsoft.AspNetCore.Authentication.JwtBearer    - ACHTUNG: korrekte Version
            builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
                .AddJwtBearer(options => {
                    options.TokenValidationParameters = new TokenValidationParameters {
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(builder.Configuration.GetSection("AppSettings:Token").Value)),
                        // ValidateIssuer / ValidateAudience https://stackoverflow.com/a/70597593/2042829
                        ValidateIssuer = false,
                        ValidateAudience = false
                    };
                });
            // ---

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (app.Environment.IsDevelopment()) {
                app.UseSwagger();
                app.UseSwaggerUI();
            }

            app.UseHttpsRedirection();

            // --- must be above of UseAuthorization
            app.UseAuthentication();
            // ---

            app.UseAuthorization();


            app.MapControllers();

            app.Run();
        }
    }
}