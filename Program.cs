var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
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

app.MapPost("/encrypt", (EncryptionRequest req) =>
{
    if (string.IsNullOrEmpty(req.Text) || string.IsNullOrEmpty(req.Key))
        return Results.BadRequest("Texto y clave son obligatorios.");

    string encryptedText = Seguridad.GetHash(req.Text, Seguridad.Encripta(req.Key), Seguridad.HashAlgorithm.SHA512);//Seguridad.EncryptString(req.Text, req.Key);
    return Results.Ok(new { EncryptedText = encryptedText });
});

app.Run();

// Clase para el cuerpo de la petición
record EncryptionRequest(string Text, string Key);


