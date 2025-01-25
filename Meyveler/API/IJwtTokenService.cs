namespace FruitAPI
{
    public interface IJwtTokenService
    {
        string GenerateToken(string username);
    }


}
