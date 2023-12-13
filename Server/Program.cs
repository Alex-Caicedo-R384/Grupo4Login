using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;
using System.Threading.Tasks;

public interface IAuthenticationService
{
    Task<AuthenticationState> GetAuthenticationStateAsync();
    Task<AuthenticationResult> Login(LoginModel loginModel);
    Task Logout();
}

public class AuthenticationService : IAuthenticationService
{
    private readonly AuthenticationStateProvider authenticationStateProvider;
    private readonly NavigationManager navigationManager;

    public AuthenticationService(AuthenticationStateProvider authenticationStateProvider, NavigationManager navigationManager)
    {
        this.authenticationStateProvider = authenticationStateProvider;
        this.navigationManager = navigationManager;
    }

    public async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        return await authenticationStateProvider.GetAuthenticationStateAsync();
    }

    public async Task<AuthenticationResult> Login(LoginModel loginModel)
    {
        if (loginModel.NombreUsuario == "usuario" && loginModel.Contraseña == "contraseña")
        {
            var identity = new ClaimsIdentity(new[]
            {
                new Claim(ClaimTypes.Name, loginModel.NombreUsuario),
            }, "custom");
            var user = new ClaimsPrincipal(identity);
            var authenticationState = new AuthenticationState(user);
            NotifyAuthenticationStateChanged(Task.FromResult(authenticationState));
            return AuthenticationResult.Success;
        }
        else
        {
            return AuthenticationResult.Failed("Credenciales inválidas");
        }
    }

    public async Task Logout()
    {
        await authenticationStateProvider.SetAuthenticationStateAsync(new AuthenticationState(new ClaimsPrincipal()));
        navigationManager.NavigateTo("/logout");
    }

    private void NotifyAuthenticationStateChanged(Task<AuthenticationState> task)
    {
        authenticationStateProvider.NotifyAuthenticationStateChanged(task);
    }
}

public class AuthenticationResult
{
    public bool Succeeded { get; set; }
    public string ErrorMessage { get; set; }

    public static AuthenticationResult Success => new AuthenticationResult { Succeeded = true };
    public static AuthenticationResult Failed(string errorMessage) => new AuthenticationResult { Succeeded = false, ErrorMessage = errorMessage };
}
