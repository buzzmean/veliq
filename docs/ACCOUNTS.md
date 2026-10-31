# Аккаунты, подписки, оплата

Личный кабинет на сайте, подписки игроков и клубов, коды активации из кабинета и
отключение по окончании оплаченного периода. Всё выключено по умолчанию: без
флагов сервер ведёт себя как раньше.

## Как устроено

- **Аккаунт** — только почта. Вход по шестизначному коду из письма (10 минут,
  5 попыток, повторная отправка не чаще раза в минуту). Паролей нет.
- **Сессия** — cookie `veliq_session` (HttpOnly, Secure, SameSite=Strict,
  Path `/api/v1/account`), 30 дней. В базе хранится только хеш.
- **Подписка** — `player` (1 место) или `club` (N мест), `paid_until`,
  автопродление. У каждой подписки один код активации (`activation_codes.subscription_id`);
  код показывается один раз, «получить код» выпускает новый, занятые места сохраняются.
- **Место** — это `activation_slots`. «Освободить» в кабинете удаляет слот, отзывает
  устройство и публикует конфигурацию.
- **Платёж** — `payments`, идемпотентно по `(provider, provider_payment_id)`.
  Успешный платёж продлевает: `paid_until = max(сейчас, paid_until) + period_days`.
- **Льготный период** — 72 часа после `paid_until`.
- **Старые коды** (без подписки) считаются оплаченными до `expires_at` кода.
  Устройства без кода не ограничиваются никогда.

Схема — `services/control-plane/migrations/004_accounts_subscriptions.sql`
(только добавления, версия схемы 4).

## API

Кабинет (тот же домен, что сайт; не-GET — только JSON и `Origin` = `-account-origin`):

| Метод | Путь | Что делает |
|---|---|---|
| POST | `/api/v1/account/login/start` | `{email}` → письмо с кодом |
| POST | `/api/v1/account/login/verify` | `{email, code}` → cookie |
| POST | `/api/v1/account/logout` | завершить сессию |
| GET | `/api/v1/account` | почта, подписки, места, платежи, тарифы, `payments_enabled` |
| POST | `/api/v1/account/subscriptions` | `{plan_id, seats}` → новая подписка |
| POST | `/api/v1/account/subscriptions/{id}/code` | новый код активации |
| POST | `/api/v1/account/subscriptions/{id}/auto-renew` | `{enabled}` |
| POST | `/api/v1/account/subscriptions/{id}/devices/{machine}/release` | освободить место |
| POST | `/api/v1/account/subscriptions/{id}/pay` | ссылка на оплату (`redirect`) |
| POST | `/api/v1/payments/webhook` | уведомление платёжного сервиса |

Ошибки — коды строкой (`EMAIL_INVALID`, `LOGIN_CODE_INVALID`, `ACCOUNT_RATE_LIMIT`,
`ACCOUNT_NOT_CONFIGURED`, `PAYMENT_NOT_CONFIGURED`, `PRICE_NOT_SET` …); тексты для
людей — в `website/assets/account.js`.

Устройство: `POST /api/v1/subscription/status` с подписанным одноразовым
доказательством (`RelayID = "subscription-status"`) → `{managed, enforced, active,
paid_until, grace_until}`. Никаких персональных данных.

Администратор (`Authorization` как у остальных admin-методов):

- `GET /api/v1/admin/subscriptions` — все подписки;
- `GET /api/v1/admin/subscriptions/cutoff` — какие устройства остановятся, если включить проверку сейчас;
- `POST /api/v1/admin/subscriptions/payments` — `{subscription_id, amount_kopecks, period_days, reference}`:
  ручное зачисление оплаты по счёту (повтор с тем же `reference` ничего не меняет).

## Флаги control-plane

| Флаг | Назначение |
|---|---|
| `-account-origin https://veliq.app` | включает кабинет; пусто — API кабинета отвечает 503 |
| `-plans-file /etc/neexitlag/plans.json` | тарифы, пример — `deploy/vps/plans.example.json` (цена 0 = оплата закрыта) |
| `-smtp-addr host:465`, `-smtp-from`, `-smtp-user`, `-smtp-password-file` | отправка кодов входа (465 — TLS сразу, иначе STARTTLS обязателен) |
| `-platega-merchant-id`, `-platega-secret-file` | онлайн-оплата через Platega; webhook — `POST /api/v1/payments/webhook`, URL задаётся в кабинете Platega |
| `-enforce-subscription` | отказ в билетах релея (402 `SUBSCRIPTION_EXPIRED`) для неоплаченных устройств |

### Платежи Platega

Адаптер — `services/control-plane/platega.go`. Создание платежа:
`POST https://app.platega.io/v2/transaction/process` (метод выбирает плательщик
на форме Platega), авторизация заголовками `X-MerchantId`/`X-Secret`,
`metadata.user_email` — email аккаунта, `payload` — `veliq:sub:<id подписки>`.
Webhook проверяет те же заголовки сравнением в constant time (HMAC-SHA256 —
только у Payout API); зачисление идемпотентно по id транзакции, повторы и
внеочередная доставка безопасны, сумма сверяется с ожидающей записью, чужой
платёж отклоняется. Автопродление (paymentMethod 6) выключено: запрос с
`auto_renew` отвечает 409 `PAYMENT_AUTORENEW_UNAVAILABLE` до подтверждения
рекуррентных СБП-подписок менеджером Platega.

## Клиент

Служба раз в 6 часов (каждые 10 минут после ошибки или пока подписка закончилась)
спрашивает `subscription/status`. Если `enforced && !active`, VELIQ выключается
обратимо: личность, сертификат и активация остаются. После оплаты кнопка
«Я уже оплатил — проверить» (IPC `subscription.refresh`) возвращает работу без
нового кода и перезапуска. Ошибка сети никогда не считается окончанием подписки.
Отказ релея с 402 запускает внеочередную проверку.

IPC: `subscription.status` → `{state: UNKNOWN|UNMANAGED|ACTIVE|EXPIRED, paid_until,
grace_until, checked_at}`, `subscription.refresh` — то же плюс проверка сейчас.
Оба разрешены в клубном режиме.

## Сайт

`website/account.html` (генерирует `design/tools/build-site.py`) +
`website/assets/account.js`. Ходит в `/api/v1/account` на том же домене, поэтому
обратный прокси сайта должен отдавать `/api/` в control-plane и передавать
`X-Real-IP` (ему доверяют только с loopback). Пока `ACCOUNT_URL = None` в
`build-site.py`, кнопки «Оформить подписку» ведут на почту, а страница кабинета
не связана с меню и закрыта в `robots.txt`.

## Порядок включения

1. Выкатить control-plane (миграция 4 применяется сама), положить `plans.json`
   с ценами, настроить SMTP, `-account-origin`.
2. Прокси: `/api/` → control-plane; проверить вход в кабинет.
3. `ACCOUNT_URL = "account.html"`, пересобрать сайт.
4. Подключить платёжный сервис (адаптер `PaymentProvider`), проверить тестовый платёж.
5. Посмотреть `GET /api/v1/admin/subscriptions/cutoff`; когда список пуст или
   согласован — включить `-enforce-subscription`.
