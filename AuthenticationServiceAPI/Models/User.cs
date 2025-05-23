using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace AuthService.Models;

public class User
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    [BsonElement("username")]
    public string Username { get; set; }
        
    [BsonElement("password")]
    public string Password { get; set; }
        
    [BsonElement("firstName")]
    public string FirstName { get; set; }
        
    [BsonElement("lastName")]
    public string LastName { get; set; }
        
    [BsonElement("address")]
    public string Address { get; set; }
        
    [BsonElement("phone")]
    public string Phone { get; set; }
        
    [BsonElement("email")]
    public string Email { get; set; }
        
    [BsonElement("isAdmin")]
    public bool IsAdmin { get; set; }
}