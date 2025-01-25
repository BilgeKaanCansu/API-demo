using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Claims;
using System.Text.Json;
using System.Text.Encodings.Web;
using FruitAPI;

public class LdapAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
{
    private readonly string _ldapServer = "127.0.0.1";
    private readonly int _ldapPort = 10389;
    private readonly string _ldapBaseDN = "ou=system";
    private readonly string _ldapUserDnTemplate = "cn={0},ou=users,{1}";

    public LdapAuthenticationHandler(
        IOptionsMonitor<AuthenticationSchemeOptions> options,
        ILoggerFactory logger,
        UrlEncoder encoder,
        ISystemClock clock) : base(options, logger, encoder, clock)
    { }

    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var body = await new StreamReader(Context.Request.Body).ReadToEndAsync();
        if (string.IsNullOrWhiteSpace(body))
            return AuthenticateResult.Fail("Request body is empty.");

        LoginModel loginModel;
        try
        {
            loginModel = JsonSerializer.Deserialize<LoginModel>(body);
        }
        catch (JsonException)
        {
            return AuthenticateResult.Fail("Invalid JSON format.");
        }

        var username = loginModel?.Username;
        var password = loginModel?.Password;

        if (string.IsNullOrEmpty(username) || string.IsNullOrEmpty(password))
            return AuthenticateResult.Fail("Invalid credentials.");

        using (var connection = new LdapConnection(new LdapDirectoryIdentifier(_ldapServer, _ldapPort)))
        {
            connection.AuthType = AuthType.Basic;
            var userDn = string.Format(_ldapUserDnTemplate, username, _ldapBaseDN);

            try
            {
                connection.Bind(new NetworkCredential(userDn, password));
                var userGroups = GetUserGroups(connection, userDn);

                var claims = new List<Claim> { new Claim(ClaimTypes.Name, username) };
                foreach (var group in userGroups)
                {
                    if (group == "Manav" || group == "Halci")
                        claims.Add(new Claim(ClaimTypes.Role, group));
                }

                var identity = new ClaimsIdentity(claims, "LDAP");
                var principal = new ClaimsPrincipal(identity);
                var ticket = new AuthenticationTicket(principal, "LDAP");

                return AuthenticateResult.Success(ticket);
            }
            catch (LdapException)
            {
                return AuthenticateResult.Fail("LDAP Authentication failed.");
            }
        }
    }

    private List<string> GetUserGroups(LdapConnection connection, string userDn)
    {
        var groups = new List<string>();
        var filter = $"(&(objectClass=groupOfNames)(member={userDn}))";

        var request = new SearchRequest(_ldapBaseDN, filter, SearchScope.Subtree, "cn");
        var response = (SearchResponse)connection.SendRequest(request);

        foreach (SearchResultEntry entry in response.Entries)
        {
            var groupName = entry.Attributes["cn"]?[0].ToString();
            if (!string.IsNullOrEmpty(groupName))
                groups.Add(groupName);
        }
        return groups;
    }
}