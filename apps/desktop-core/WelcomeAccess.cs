namespace Neexitlag.Desktop;

// Presentation gate only. The service remains authoritative for activation,
// subscription, club policy and every routing operation. No local "signed in" bit.
public sealed record WelcomeAccess(string State, string Title, string Message, bool CanContinue)
{
    public static WelcomeAccess Evaluate(ActivationView activation, AccountConnectionView account, SubscriptionView subscription)
    {
        if (activation.State == "UNAVAILABLE" || account.State == "UNAVAILABLE")
            return new("UNAVAILABLE", "Не удалось связаться с VELIQ", "Проверьте, что служба VELIQ запущена, и повторите проверку.", false);
        if (subscription.Expired)
            return new("EXPIRED", "Подписка закончилась", "Продлите подписку в личном кабинете, затем нажмите «Проверить подключение».", false);
        if (account.ImageReady || account.ImagePreparation)
            return new("MANAGED", "Подготовка клубного компьютера", "Завершите подготовку с администратором клуба. Личный вход игрока не требуется.", false);
        if (account.State is "STARTING" or "WAITING_FOR_BROWSER")
            return new("WAITING", "Подтвердите вход в VELIQ", "Введите почту и код из письма, затем подтвердите подключение компьютера.", false);
        if (activation.Error.Length > 0)
            return new("ERROR", "Не удалось подключить компьютер", activation.Message, false);
        if (account.Error.Length > 0 || account.State is "ERROR" or "EXPIRED" or "SIGN_IN_REQUIRED")
            return new("ERROR", "Нужно подтвердить аккаунт", account.Message, false);
        bool activated = activation.State == "ACTIVATED" && activation.HasIdentity && activation.CapturePermitted;
        if (activated && account.Linked && account.Kind is "player" or "club")
            return new("READY", "Вы вошли в VELIQ", "Подключение сохранено. Можно переходить к настройке приложений.", true);
        // Older issued activation codes have no personal account binding. They
        // remain valid credentials, but never grant administrator/club mode here.
        if (activated && account.State == "NOT_LINKED" && account.Kind.Length == 0)
            return new("CODE_READY", "Компьютер подключён по коду", "Сохранённый код уже активировал этот компьютер. Повторно вводить его не нужно.", true);
        if (activation.State == "ACTIVATING")
            return new("ACTIVATING", "Подключаем компьютер", "Проверяем подключение. Это может занять некоторое время.", false);
        if (activation.HasIdentity && !activation.CapturePermitted)
            return new("BLOCKED", "Подключение пока недоступно", "Проверьте доступ к интернету и состояние подписки. Если это клубный ПК, обратитесь к администратору.", false);
        return new("SIGN_IN", "Добро пожаловать в VELIQ", "Войдите в свой аккаунт или подключите компьютер кодом, выданным администратором.", false);
    }
}
