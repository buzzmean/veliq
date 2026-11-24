namespace Neexitlag.Desktop;

// Machine activation and cabinet sign-in are independent. A code-activated PC
// does not need a personal account, and cannot infer a subscription kind from it.
public sealed record SettingsConnection(string Title, string Hint, bool ShowCabinet)
{
    public static SettingsConnection Evaluate(ActivationView activation, AccountConnectionView account)
    {
        if (activation.HasIdentity && activation.State == "ACTIVATED" && activation.Error.Length == 0)
        {
            if (account.Kind == "club")
                return new("Клубная подписка", "Компьютер подключён", account.Linked);
            if (account.Linked)
                return new(account.Summary, "Компьютер подключён", true);
            return new("Компьютер подключён", "Активирован по коду", false);
        }
        if (activation.Error.Length > 0 || activation.State == "UNAVAILABLE")
            return new("Проверьте подключение", activation.Message, account.Linked);
        if (account.Linked)
            return new(account.Summary, account.Message, true);
        return new("Компьютер не подключён", "Войдите в аккаунт или используйте код активации", true);
    }
}
