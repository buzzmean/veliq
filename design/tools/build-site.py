#!/usr/bin/env python3
"""Генерирует статические страницы website/*.html с общей шапкой и подвалом.

Результат — обычный HTML без сборщика: его можно править руками, но тогда правку шапки/подвала
придётся повторить на всех страницах. Проще поменять здесь и запустить:
    python3 design/tools/build-site.py
Все данные о версии и адресах — в словарях SITE и RELEASE ниже.
"""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "website"

SITE = {
    "url": "https://veliq.app",          # ДОПУЩЕНИЕ: домен не выбран, заменить здесь
    "email": "support@veliq.app",        # ДОПУЩЕНИЕ: адрес поддержки не выбран
    "name": "VELIQ",
}
# Продавец и цены. Пока поле пустое, на страницах оплаты и правовых документах показывается пометка «Черновик».
SELLER = {
    "name": "",                          # ФИО полностью, как в «Мой налог»
    "inn": "",                           # ИНН (12 цифр)
    "status": "плательщик налога на профессиональный доход (самозанятый)",
    "email": SITE["email"],
    "phone": "",                         # необязательно
}
PRICES = {                               # рубли; None — цена ещё не утверждена
    "player_month": None,                # «Игрок», 1 компьютер, месяц
    "club_pc_month": None,               # «Клуб», за компьютер в месяц
}
OFFER_DATE = "1 ноября 2026"             # дата редакции оферты и политики
ACCOUNT_URL = None                       # адрес личного кабинета, например "account.html"; None — кабинет ещё не запущен
PAYMENT_AGENT = "ЮKassa (ООО НКО «ЮМани»)"  # платёжный сервис для карт и СБП
LOG_RETENTION = None                     # срок хранения журналов соединений на серверах, например "30 дней"


def rub(v):
    return "— ₽" if v is None else f"{v:,} ₽".replace(",", "\u00a0")


def seller_line():
    """Реквизиты одной строкой: ФИО, статус, ИНН."""
    if not SELLER["name"]:
        return ""
    return f'{SELLER["name"]}, {SELLER["status"]}, ИНН {SELLER["inn"]}'


SELLER_READY = bool(SELLER["name"] and SELLER["inn"])
PRICES_READY = all(v is not None for v in PRICES.values())
RELEASE = {
    "version": "1.0 beta",               # ДОПУЩЕНИЕ: номер версии подставить при выпуске
    "date": "20 октября 2026",
    "size": "≈ 40 МБ",
    "file": "VELIQ-Setup.exe",
    "url": "downloads/VELIQ-Setup.exe",  # ДОПУЩЕНИЕ: ссылка на файл установщика
    "sha256": "появится вместе с файлом установщика",
    "os": "Windows 10 и 11, 64-бит",
}

NAV = [
    ("how.html", "Как работает", "how"),
    ("index.html#games", "Игры", "games"),
    ("clubs.html", "Клубам", "clubs"),
    ("pricing.html", "Цены", "pricing"),
    ("support.html", "Помощь", "support"),
]


def icon(name, cls="i"):
    return f'<svg class="{cls}" aria-hidden="true"><use href="#i-{name}"/></svg>'


def head(title, desc, path, extra_ld=None, og="og-image.png", og_alt="VELIQ: нажал — работает."):
    url = f'{SITE["url"]}/{path if path != "index.html" else ""}'
    ld = ""
    if extra_ld:
        ld = f'\n  <script type="application/ld+json">{json.dumps(extra_ld, ensure_ascii=False)}</script>'
    full_title = title if title.startswith("VELIQ") else f"{title} — VELIQ"
    return f"""<!doctype html>
<html lang="ru">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>{html.escape(full_title)}</title>
  <meta name="description" content="{html.escape(desc)}">
  <link rel="canonical" href="{url}">
  <meta name="theme-color" content="#0A0A0B">
  <meta name="color-scheme" content="light dark">
  <meta property="og:type" content="website">
  <meta property="og:site_name" content="VELIQ">
  <meta property="og:locale" content="ru_RU">
  <meta property="og:title" content="{html.escape(full_title)}">
  <meta property="og:description" content="{html.escape(desc)}">
  <meta property="og:url" content="{url}">
  <meta property="og:image" content="{SITE['url']}/assets/img/{og}">
  <meta property="og:image:width" content="1200">
  <meta property="og:image:height" content="630">
  <meta property="og:image:alt" content="{html.escape(og_alt)}">
  <meta name="twitter:card" content="summary_large_image">
  <meta name="twitter:image" content="{SITE['url']}/assets/img/{og}">
  <link rel="icon" href="assets/img/favicon.svg" type="image/svg+xml">
  <link rel="icon" href="assets/img/favicon.ico" sizes="any">
  <link rel="apple-touch-icon" href="assets/img/app-icon-180.png">
  <link rel="manifest" href="site.webmanifest">
  <link rel="preload" href="assets/fonts/Onest-var.woff2" as="font" type="font/woff2" crossorigin>
  <link rel="stylesheet" href="assets/tokens.css">
  <link rel="stylesheet" href="assets/components.css">
  <link rel="stylesheet" href="assets/site.css">
  <script>document.documentElement.classList.add('js');try{{var t=localStorage.getItem('veliq-theme');if(t)document.documentElement.setAttribute('data-theme',t)}}catch(e){{}}</script>{ld}
</head>
<body>
<script src="assets/icons.js"></script>
<a class="skip" href="#main">Перейти к содержанию</a>
"""


def header(active):
    links = "\n".join(
        f'      <a href="{href}"{" aria-current=\"page\"" if key == active else ""}>{label}</a>'
        for href, label, key in NAV
    )
    return f"""<header class="top">
  <div class="wrap top__in">
    <a class="logo" href="index.html" aria-label="VELIQ — на главную">
      <img class="on-light" src="assets/img/veliq-wordmark-light.svg" alt="VELIQ" width="144" height="66">
      <img class="on-dark" src="assets/img/veliq-wordmark-dark.svg" alt="" width="144" height="66">
    </a>
    <nav class="nav" id="nav" aria-label="Основное меню">
{links}
    </nav>
    <div class="top__tools">
      <button class="btn btn--quiet btn--icon btn--sm theme-btn" type="button" data-theme-toggle aria-label="Сменить тему">
        <svg class="i i-sun-use" aria-hidden="true"><use href="#i-sun"/></svg><svg class="i i-moon-use" aria-hidden="true"><use href="#i-moon"/></svg>
      </button>
      <a class="btn btn--sm top__cta" href="download.html">Скачать</a>
      <button class="btn btn--quiet btn--icon btn--sm menu-btn" type="button" data-menu aria-expanded="false" aria-controls="nav" aria-label="Меню">{icon('menu')}</button>
    </div>
  </div>
</header>
"""


def footer():
    return f"""<footer class="foot">
  <div class="wrap">
    <div class="foot__grid">
      <div>
        <a class="logo" href="index.html" aria-label="VELIQ — на главную">
          <img class="on-light" src="assets/img/veliq-wordmark-light.svg" alt="VELIQ" width="144" height="66">
          <img class="on-dark" src="assets/img/veliq-wordmark-dark.svg" alt="" width="144" height="66">
        </a>
        <p class="muted" style="max-width:34ch;margin:16px 0 0">Оптимальный маршрут для каждого соединения.</p>
      </div>
      <div>
        <h2>Продукт</h2>
        <ul><li><a href="download.html">Скачать</a></li><li><a href="how.html">Как работает</a></li><li><a href="index.html#privacy">Что видит сервер</a></li><li><a href="index.html#games">Для игр</a></li><li><a href="pricing.html">Цены</a></li><li><a href="roadmap.html">План развития</a></li></ul>
      </div>
      <div>
        <h2>Клубам</h2>
        <ul><li><a href="clubs.html">VELIQ для клубов</a></li><li><a href="clubs.html#calc">Расчёт выгоды</a></li><li><a href="clubs.html#setup">Установка в клубе</a></li></ul>
      </div>
      <div>
        <h2>Помощь</h2>
        <ul><li><a href="support.html">Вопросы и ответы</a></li><li><a href="support.html#errors">Ошибки и решения</a></li><li><a href="contacts.html">Контакты и реквизиты</a></li><li><a href="mailto:{SITE['email']}">{SITE['email']}</a></li></ul>
      </div>
    </div>
    <div class="foot__bottom">
      <span>© 2026 VELIQ{" · " + seller_line() if seller_line() else ""}</span>
      <span><a href="privacy.html">Конфиденциальность</a>&nbsp;&nbsp;&nbsp;<a href="terms.html">Оферта</a>&nbsp;&nbsp;&nbsp;<a href="contacts.html">Контакты</a></span>
    </div>
  </div>
</footer>
<script src="assets/charts.js"></script>
<script src="assets/site.js"></script>
</body>
</html>
"""


def page(path, title, desc, active, body, ld=None, og="og-image.png", og_alt="VELIQ: нажал — работает."):
    (OUT / path).write_text(head(title, desc, path, ld, og, og_alt) + header(active) + '<main id="main">\n' + body + "\n</main>\n" + footer(), encoding="utf-8")
    print("страница:", path)


def faq(items):
    out = []
    for q, a in items:
        out.append(f'<details><summary>{q}{icon("chevron-down")}</summary><div class="a">{a}</div></details>')
    return "\n".join(out)


# ---------------------------------------------------------------- тексты FAQ (общие)

def flow(kind):
    """Схема: устройство → (сервер) → назначения. kind = 'plain' (без VELIQ) | 'veliq'. HTML/CSS, без картинок."""
    rows = [("Онлайн-игра", "нужен низкий пинг"), ("Голосовой чат", "нужна стабильность"), ("Обычный сайт", "и так работает"), ("Банк", "и так работает")]
    out = []
    if kind == "plain":
        out.append('<div class="flow flow--vpn" data-trace>')
        out.append('<div class="flow__src">Вы</div><div class="flow__hub">Провайдер</div>')
        for i, (name, _) in enumerate(rows):
            out.append(f'<span class="flow__a" style="grid-row:{i+1}"></span><span class="flow__b" style="grid-row:{i+1}"></span><span class="flow__dst" style="grid-row:{i+1}">{name}</span>')
        out.append('</div>')
        out.append('<p class="flow__cap">Все соединения идут одним путём, который выбрал провайдер, — даже если до игрового сервера есть путь короче.</p>')
    else:
        mids = [("relay", "быстрый путь"), ("relay", "стабильный путь"), ("plain", "как обычно"), ("plain", "как обычно")]
        out.append('<div class="flow flow--veliq" data-trace>')
        out.append('<div class="flow__src">Вы</div>')
        for i, ((name, _), (mode, label)) in enumerate(zip(rows, mids)):
            g = f'grid-row:{i+1}'
            if mode == "relay":
                out.append(f'<span class="flow__a is-sig" style="{g}"></span><span class="flow__node" style="{g}">{label}</span><span class="flow__b is-sig" style="{g}"></span><span class="flow__dst" style="{g}">{name}</span>')
            else:
                out.append(f'<span class="flow__plain" style="{g}"><em>{label}</em></span><span class="flow__dst is-plain" style="{g}">{name}</span>')
        out.append('</div>')
        out.append('<p class="flow__cap">Каждое соединение получает свой путь: игры — самый быстрый маршрут, голосовые чаты — самый стабильный, остальное — как обычно.</p>')
    return "\n".join(out)


def privacy_block(head_tag="h2"):
    return f"""<div class="sec__head"><{head_tag} class="h2">Что видит сервер</{head_tag}><p>Сервер VELIQ пересылает трафик, но не может его прочитать: соединения с сайтами и приложениями зашифрованы от начала до конца.</p></div>
    <div class="seen">
      <div class="seen__path" data-trace aria-label="Путь соединения: ваше устройство, сервер VELIQ, сервис. На всём пути данные зашифрованы.">
        <span class="seen__end">Ваше устройство</span>
        <span class="seen__wire">{icon('lock','i i--sm')}<em>зашифровано</em></span>
        <span class="seen__mid">Сервер VELIQ</span>
        <span class="seen__wire">{icon('lock','i i--sm')}<em>зашифровано</em></span>
        <span class="seen__end">Сервис</span>
      </div>
      <div class="seen__cols">
        <div>
          <h3 class="h3">Видит</h3>
          <ul class="seen__list">
            <li>{icon('check','i i--sm')}<span><strong>Куда</strong> идёт соединение — адрес игрового сервера или сайта</span></li>
            <li>{icon('check','i i--sm')}<span><strong>Сколько</strong> данных передано</span></li>
            <li>{icon('check','i i--sm')}<span><strong>Ваше устройство</strong> — по ключу устройства, чтобы пускать только своих</span></li>
          </ul>
        </div>
        <div>
          <h3 class="h3">Не видит</h3>
          <ul class="seen__list seen__list--no">
            <li>{icon('close','i i--sm')}<span>Что вы смотрите и открываете на странице</span></li>
            <li>{icon('close','i i--sm')}<span>Пароли, переписку и сообщения</span></li>
            <li>{icon('close','i i--sm')}<span>Файлы, платёжные данные и содержимое игр</span></li>
          </ul>
        </div>
      </div>
      <p class="seen__note">VELIQ не расшифровывает и не подменяет HTTPS. Почти все сайты и приложения сейчас работают по HTTPS; это и даёт защиту на всём пути.</p>
    </div>"""


FAQ_MAIN = [
    ("Как VELIQ выбирает путь?", "<p>Программа замеряет задержку и потери до сервера игры или сервиса и выбирает лучший путь: обычный — через провайдера, или через собственные серверы VELIQ, если так быстрее или стабильнее. Всё, что и так работает хорошо, не трогает. <a href=\"how.html\">Как работает VELIQ</a>.</p>"),
    ("Нужно ли что-то перезапускать?", "<p>Нет. Маршруты работают сразу после нажатия «Оптимизировать» — ничего закрывать и перезапускать не нужно.</p>"),
    ("Как VELIQ влияет на пинг в играх?", "<p>VELIQ сравнивает пути до игрового сервера и выбирает самый быстрый. Если путь через сеть VELIQ не быстрее обычного, маршрут не меняется. Замеры видно в программе.</p>"),
    ("Вы видите, что я открываю?", "<p>Нет. Мы не расшифровываем и не подменяем HTTPS. Сервер видит адрес назначения и объём данных — этого достаточно, чтобы переслать трафик. <a href=\"index.html#privacy\">Что видит сервер</a>. Подробности — в <a href=\"privacy.html\">политике конфиденциальности</a>.</p>"),
    ("Какие системы поддерживаются?", "<p>Сейчас VELIQ работает на компьютерах с Windows. Версия для телефона готовится.</p>"),
    ("Сколько стоит и как оплатить?", "<p>Тарифы — на странице <a href=\"pricing.html\">«Цены»</a>. Оплатить можно картой или через СБП в личном кабинете, клубы могут платить по счёту.</p>"),
    ("Подходит ли VELIQ для клубов?", "<p>Да. Для клубов есть отдельный код активации и инструкция, они выдаются после заявки. <a href=\"clubs.html\">VELIQ для клубов</a>.</p>"),
]

# ---------------------------------------------------------------- главная
PING = {"label": "Пинг до игрового сервера: обычный путь около 73 мс, маршрут VELIQ около 41 мс. Иллюстрация.", "series": [
    {"id": "direct", "name": "обычный", "values": [71, 74, 70, 77, 72, 73, 79, 71, 70, 75, 72, 74, 73, 76, 72, 71, 74, 73, 72, 73]},
    {"id": "hel", "name": "VELIQ", "values": [42, 41, 43, 40, 41, 42, 41, 44, 41, 40, 41, 42, 41, 41, 43, 41, 40, 41, 42, 41]},
]}

index_body = f"""
<section class="hero" style="overflow-x:clip">
  <div class="wrap hero__grid">
    <div class="hero__copy">
      <h1 class="h-display hero-title">
        <span class="slit-line"><span class="slit">Нажал —</span></span>
        <span class="slit-line"><span class="slit">работает.</span><span class="slit-bar" aria-hidden="true"></span></span>
      </h1>
      <p class="lede">VELIQ сам выстраивает оптимальный маршрут для каждого соединения: игры получают самый быстрый путь до сервера, голосовые чаты и стримы — стабильную связь.</p>
      <div class="hero__actions">
        <a class="btn btn--lg" href="download.html">{icon('download')}Скачать</a>
        <a class="btn btn--lg btn--ghost" href="clubs.html">Для компьютерных клубов</a>
      </div>
      <p class="hero__meta">Бета-версия</p>
    </div>

    <div class="demo" data-demo data-state="off" aria-label="Демонстрация программы">
      <div class="demo__bar">
        <img src="assets/img/veliq-wordmark-dark.svg" alt="VELIQ" width="48" height="22">
        <span class="status status--off" data-demo-status><i class="status__mark" aria-hidden="true"></i><span>Выключено</span></span>
      </div>
      <button class="go" type="button" data-state="off" aria-pressed="false" aria-describedby="demo-hint">
        <span class="go__label"><span data-go-label>Оптимизировать</span><small data-go-sub>выключено</small></span>
      </button>
      <div class="route" aria-label="Маршруты">
        <div class="route__row route__row--relay"><span class="route__name">Игры</span><span class="route__line"></span><span class="route__via" data-on="лучший маршрут">—</span></div>
        <div class="route__row route__row--relay"><span class="route__name">Голосовой чат</span><span class="route__line"></span><span class="route__via" data-on="стабильно">—</span></div>
        <div class="route__row route__row--relay"><span class="route__name">Стримы</span><span class="route__line"></span><span class="route__via" data-on="без подвисаний">—</span></div>
        <div class="route__row route__row--relay"><span class="route__name">Сайты</span><span class="route__line"></span><span class="route__via" data-on="как обычно">—</span></div>
      </div>
      <p class="demo__hint" id="demo-hint">Нажмите кнопку — так выглядит запуск в программе.</p>
      <span class="sr-only" aria-live="polite" data-demo-live></span>
    </div>
  </div>
</section>

<section class="sec band--sunken" id="how">
  <div class="wrap">
    <div class="sec__head">
      <h2 class="h2">Три шага — и всё работает</h2>
      <p>Никаких адресов серверов и настроек. Всё это программа делает сама.</p>
    </div>
    <ol class="steps" style="list-style:none;margin:0;padding:0">
      <li class="step"><span class="step__n">1</span><h3 class="h3">Получите код активации</h3><p>Для клуба он выдаётся после заявки, для игрока — отдельно.</p></li>
      <li class="step"><span class="step__n">2</span><h3 class="h3">Установите VELIQ</h3><p>Установщик сделает всё сам.</p></li>
      <li class="step"><span class="step__n">3</span><h3 class="h3">Введите код — и всё работает</h3><p>После этого VELIQ готов к работе.</p></li>
    </ol>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <div class="sec__head">
      <h2 class="h2">Свой путь для каждого соединения</h2>
      <p>Играм нужна скорость, голосовым чатам и стримам — стабильность. VELIQ понимает разницу и подбирает маршрут сам, без списков и настроек.</p>
    </div>
    <div class="split">
      <div class="split__col">
        <h3 class="h3">Стабилизирует</h3>
        <ul class="split__list">
          <li><span class="mono">{icon('ping','i i--sm')}</span><span>Голосовые чаты</span><span>связь без обрывов</span></li>
          <li><span class="mono">{icon('diagnostics','i i--sm')}</span><span>Стримы и видео</span><span>без подвисаний</span></li>
          <li><span class="mono">{icon('download','i i--sm')}</span><span>Лаунчеры и обновления игр</span><span>стабильная загрузка</span></li>
          <li><span class="mono">{icon('route','i i--sm')}</span><span>Другие онлайн-сервисы</span><span>лучший из путей</span></li>
        </ul>
        <p class="split__note">Свой сайт или приложение можно добавить в программе — VELIQ подберёт для него маршрут.</p>
      </div>
      <div class="split__col">
        <h3 class="h3">Ускоряет</h3>
        <ul class="split__list">
          <li><span class="mono">{icon('games','i i--sm')}</span><span>Онлайн-игры</span><span>самый быстрый путь</span></li>
          <li><span class="mono">{icon('globe','i i--sm')}</span><span>Игровые серверы в Европе</span><span>низкий пинг</span></li>
          <li><span class="mono">{icon('check','i i--sm')}</span><span>То, что и так работает быстро</span><span>не трогаем</span></li>
        </ul>
        <p class="split__note">VELIQ замеряет задержку и выбирает путь, на котором она меньше.</p>
      </div>
    </div>
    <a class="more" href="how.html">Как работает VELIQ {icon('chevron-right','i i--sm')}</a>
  </div>
</section>

<section class="sec sec--tight">
  <div class="wrap">
    <div class="facts">
      <div class="fact fact--wide"><h3>Ничего не нужно перезапускать</h3><p>Маршруты работают сразу и везде: открытые вкладки, входы в аккаунты и загрузки остаются на месте.</p></div>
      <div class="fact"><h3>Своя сеть серверов</h3><p>Собственные серверы, а не общие бесплатные узлы, где скорость делят тысячи людей.</p></div>
      <div class="fact fact--r"><h3>HTTPS не расшифровывается</h3><p>Сервер пересылает зашифрованный трафик как есть. Пароли и переписка ему не видны.</p></div>
      <div class="fact"><h3>Ничего не настраивать</h3><p>Одна кнопка. Если что-то пошло не так, программа скажет, что именно, и предложит решение.</p></div>
      <div class="fact fact--r"><h3>Готово для клубов</h3><p>VELIQ подходит для компьютерных клубов: настраивается один раз, гостю ничего делать не нужно.</p></div>
    </div>
  </div>
</section>

<section class="sec" id="privacy">
  <div class="wrap">
    {privacy_block()}
  </div>
</section>

<section class="sec band--sunken" id="games">
  <div class="wrap games">
    <div>
      <h2 class="h2">Оптимальный маршрут для игр</h2>
      <p class="lede" style="margin-top:20px">VELIQ сравнивает пути до игрового сервера и выбирает самый быстрый. Если лучше обычного пути нет, ничего не меняется.</p>
      <ul class="ticks">
        <li>{icon('check')}<span>Стабильное подключение к игровым серверам в других регионах</span></li>
        <li>{icon('check')}<span>Меньший пинг, если через сеть VELIQ путь короче, чем у провайдера</span></li>
        <li>{icon('check')}<span>Маршрут перестраивается сам, если какой-то путь стал хуже</span></li>
      </ul>
    </div>
    <figure class="games__panel" style="margin:0">
      <header><strong>Пинг до игрового сервера (иллюстрация)</strong><ul class="legend"><li><i class="direct"></i>обычный путь</li><li><i class="hel"></i>маршрут VELIQ</li></ul></header>
      <div data-ping-chart='{json.dumps(PING, ensure_ascii=False)}'></div>
      <footer>Иллюстрация. Настоящий замер VELIQ делает на вашем компьютере и у вашего провайдера.</footer>
    </figure>
  </div>
</section>

<section class="sec band--ink">
  <div class="wrap club-band">
    <div>
      <h2 class="h2">VELIQ для компьютерных клубов</h2>
      <p class="lede" style="margin-top:20px">Быстрый путь для игр и стабильная связь на всех компьютерах клуба. Гостю ничего настраивать не нужно.</p>
      <div class="hero__actions" style="margin-top:32px"><a class="btn btn--lg" href="clubs.html">VELIQ для клубов</a><a class="btn btn--lg btn--ghost" href="clubs.html#calc">Посчитать выгоду</a></div>
    </div>
    <div class="club-band__pcs" aria-hidden="true">{''.join('<i></i>' for _ in range(27))}</div>
  </div>
</section>

<section class="sec" id="download">
  <div class="wrap">
    <div class="get">
      <img class="get__icon" src="assets/img/app-icon.svg" alt="" width="88" height="88">
      <div>
        <h2 class="h3" style="font-size:var(--fs-3xl)">VELIQ</h2>
        <ul class="get__meta"><li>Версия {RELEASE['version']}</li></ul>
      </div>
      <a class="btn btn--lg" href="download.html">{icon('download')}Скачать</a>
    </div>
  </div>
</section>

<section class="sec sec--tight" id="faq" style="padding-top:0">
  <div class="wrap">
    <div class="sec__head"><h2 class="h2">Частые вопросы</h2><p>Не нашли ответ — <a href="support.html">все вопросы и ошибки</a> или напишите на {SITE['email']}.</p></div>
    <div class="faq">
{faq(FAQ_MAIN)}
    </div>
  </div>
</section>
"""

LD_APP = {
    "@context": "https://schema.org", "@type": "SoftwareApplication", "name": "VELIQ",
    "operatingSystem": "Windows 10, Windows 11", "applicationCategory": "UtilitiesApplication",
    "description": "VELIQ строит оптимальный маршрут для каждого соединения: игры получают самый быстрый путь, голосовые чаты и стримы — стабильную связь.",
    "softwareVersion": RELEASE["version"], "url": SITE["url"],
}
LD_FAQ = {"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": [
    {"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": html.unescape(a.replace("<p>", "").replace("</p>", ""))}} for q, a in FAQ_MAIN]}

page("index.html", "VELIQ — нажал, и работает",
     "VELIQ сам строит оптимальный маршрут: игры получают самый быстрый путь, голосовые чаты и стримы — стабильную связь. Для Windows 10 и 11.",
     "", index_body, [LD_APP, LD_FAQ])

# ---------------------------------------------------------------- как работает
HOW_ROWS = [
    ("Онлайн-игры", "Путь выбирает провайдер, даже если он длиннее", "Самый быстрый путь до игрового сервера"),
    ("Голосовые чаты и стримы", "Обрывы и подвисания на загруженных участках сети", "Стабильный путь, в том числе через собственные серверы"),
    ("Сайты, которые и так работают", "Как обычно", "Как обычно — VELIQ их не трогает"),
    ("Если путь стал хуже", "Ничего не меняется", "Маршрут перестраивается сам"),
    ("Что нужно сделать", "—", "Нажать одну кнопку"),
]
how_table = "\n".join(f'<tr><th scope="row">{a}</th><td data-l="Без VELIQ">{b}</td><td data-l="С VELIQ" class="vs__us">{c}</td></tr>' for a, b, c in HOW_ROWS)
how_body = f"""
<section class="page-head">
  <div class="wrap">
    <div class="crumbs"><a href="index.html">Главная</a> / Как работает</div>
    <h1 class="h1" style="max-width:16ch">Как работает VELIQ</h1>
    <p class="lede">Обычно все соединения компьютера идут одним путём, который выбрал провайдер. VELIQ замеряет пути и для каждого соединения выбирает лучший — поэтому игры получают быстрый путь, голосовые чаты и стримы — стабильный, а остальное не замедляется.</p>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <div class="flows">
      <figure class="flows__panel">
        <figcaption><h2 class="h3">Без VELIQ</h2><span class="faint">один путь для всего</span></figcaption>
        {flow('plain')}
      </figure>
      <figure class="flows__panel flows__panel--main">
        <figcaption><h2 class="h3">С VELIQ</h2><span class="faint">свой путь для каждого соединения</span></figcaption>
        {flow('veliq')}
      </figure>
    </div>
  </div>
</section>

<section class="sec band--sunken">
  <div class="wrap">
    <div class="sec__head"><h2 class="h2">По пунктам</h2><p>Как это ощущается в обычный день: в игре, в голосовом чате, когда путь стал хуже.</p></div>
    <div class="vs-wrap">
      <table class="vs">
        <thead><tr><th scope="col"><span class="sr-only">Что сравниваем</span></th><th scope="col">Без VELIQ</th><th scope="col" class="vs__us">С VELIQ</th></tr></thead>
        <tbody>
{how_table}
        </tbody>
      </table>
    </div>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    {privacy_block()}
  </div>
</section>

<section class="sec band--ink">
  <div class="wrap club-band">
    <div>
      <h2 class="h2">Нажал — работает.</h2>
      <p class="lede" style="margin-top:20px">Никаких серверов на выбор и настроек. VELIQ строит маршруты сам.</p>
      <div class="hero__actions" style="margin-top:32px"><a class="btn btn--lg" href="download.html">{icon('download')}Скачать</a><a class="btn btn--lg btn--ghost" href="support.html">Вопросы и ответы</a></div>
    </div>
  </div>
</section>
"""
page("how.html", "Как работает VELIQ",
     "VELIQ замеряет пути и для каждого соединения выбирает лучший: игры получают самый быстрый маршрут, голосовые чаты — стабильный, остальное работает как обычно.",
     "how", how_body)

# ---------------------------------------------------------------- скачать
download_body = f"""
<section class="page-head">
  <div class="wrap">
    <div class="crumbs"><a href="index.html">Главная</a> / Скачать</div>
    <h1 class="h1">Скачать VELIQ</h1>
    <p class="lede">Установщик сделает всё сам. После установки введите код активации.</p>
    <div class="platforms" role="group" aria-label="Устройство">
      <button type="button" class="platforms__btn" data-platform-btn="win" aria-pressed="true">Компьютер</button>
      <button type="button" class="platforms__btn" data-platform-btn="phone" aria-pressed="false">Телефон<span class="platforms__soon">скоро</span></button>
    </div>
  </div>
</section>
<section class="sec sec--tight" data-platform="phone" hidden>
  <div class="wrap">
    <div class="soon">
      <img class="get__icon" src="assets/img/app-icon.svg" alt="" width="88" height="88">
      <div>
        <h2 class="h3" style="font-size:var(--fs-3xl)">VELIQ для телефона готовится</h2>
        <p class="muted" style="margin:10px 0 0;max-width:52ch">Тот же принцип: одна кнопка и свой путь для каждого соединения. Оставьте почту — напишем, когда приложение выйдет. А пока VELIQ можно поставить на компьютер.</p>
      </div>
      <div class="soon__actions">
        <a class="btn btn--lg" href="mailto:{SITE['email']}?subject=Сообщить%20о%20выходе%20VELIQ%20для%20телефона">Сообщить о выходе</a>
        <button type="button" class="btn btn--lg btn--ghost" data-platform-btn="win" aria-pressed="false">Версия для компьютера</button>
      </div>
    </div>
  </div>
</section>
<section class="sec sec--tight" data-platform="win">
  <div class="wrap cols">
    <div>
      <div class="get" style="margin-bottom:var(--sp-7)">
        <img class="get__icon" src="assets/img/app-icon.svg" alt="" width="88" height="88">
        <div>
          <h2 class="h3" style="font-size:var(--fs-3xl)">VELIQ {RELEASE['version']}</h2>
          <ul class="get__meta"><li>Бета-версия</li></ul>
        </div>
        <a class="btn btn--lg" href="{RELEASE['url']}" download>{icon('download')}Скачать установщик</a>
      </div>

      <h2 class="h2" id="install" style="font-size:var(--fs-4xl);margin-bottom:var(--sp-5)">Как установить</h2>
      <ol class="olist">
        <li><div><h3>Получите код активации</h3><p>Код привязывает VELIQ к вам. Для клуба он выдаётся после заявки, для игрока — отдельно.</p></div></li>
        <li><div><h3>Установите VELIQ</h3><p>Скачайте и запустите установщик. Он сам сделает всё нужное, дополнительных шагов не требуется.</p></div></li>
        <li><div><h3>Введите код активации</h3><p>После этого VELIQ готов к работе.</p></div></li>
      </ol>
      <p class="install-more">Для клубов есть отдельная инструкция, она выдаётся вместе с кодом активации.</p>
      <p class="install-more">Подробные инструкции и ответы на частые вопросы скоро появятся в вики VELIQ.</p>
    </div>
    <aside class="aside">
      <div class="card">
        <h2 class="h3" style="margin-bottom:16px">О файле</h2>
        <dl class="kv">
          <dt>Версия</dt><dd>{RELEASE['version']}</dd>
          <dt>Система</dt><dd>{RELEASE['os']}</dd>
        </dl>
      </div>
    </aside>
  </div>
</section>
"""
page("download.html", "Скачать VELIQ",
     f"Скачайте VELIQ {RELEASE['version']}. Установщик сделает всё сам, после установки введите код активации.",
     "", download_body, LD_APP)

# ---------------------------------------------------------------- клубы
CLUB_FAQ = [
    ("Нужно ли что-то делать гостю?", "<p>Нет. Гостю ничего настраивать не нужно.</p>"),
    ("Как VELIQ влияет на пинг в играх?", "<p>VELIQ выбирает самый быстрый путь до игрового сервера. Если обычный путь быстрее, маршрут не меняется.</p>"),
    ("Подходит ли VELIQ для моей системы управления клубом?", "<p>Напишите нам, подскажем.</p>"),
    ("Сколько это стоит?", "<p>Тариф «Клуб» считается за компьютер в месяц — цена на странице <a href=\"pricing.html\">«Цены»</a>. Оплатить можно картой в личном кабинете или по счёту. Выгоду можно прикинуть <a href=\"#calc\">в калькуляторе</a>.</p>"),
]
club_calc = f"""
<div class="calc" data-calc>
  <div class="calc__in">
    <div class="calc__row"><label for="c-pcs">Компьютеров в клубе</label><input class="input" id="c-pcs" data-k="pcs" inputmode="numeric" value="20"><input type="range" data-k="pcs" min="5" max="200" step="1" value="20" aria-label="Компьютеров в клубе"></div>
    <div class="calc__row"><label for="c-hours">Часов работы в сутки</label><input class="input" id="c-hours" data-k="hours" inputmode="numeric" value="24"><input type="range" data-k="hours" min="6" max="24" step="1" value="24" aria-label="Часов работы в сутки"></div>
    <div class="calc__row"><label for="c-load">Средняя загрузка, %</label><input class="input" id="c-load" data-k="load" inputmode="numeric" value="50"><input type="range" data-k="load" min="5" max="100" step="1" value="50" aria-label="Средняя загрузка"></div>
    <div class="calc__row"><label for="c-price">Цена часа, ₽</label><input class="input" id="c-price" data-k="price" inputmode="numeric" value="150"><input type="range" data-k="price" min="40" max="500" step="10" value="150" aria-label="Цена часа"></div>
    <div class="calc__row"><label for="c-lost">Часов теряете из-за лагов и обрывов, %</label><input class="input" id="c-lost" data-k="lost" inputmode="decimal" value="3"><input type="range" data-k="lost" min="0" max="20" step="0.5" value="3" aria-label="Потерянные часы"><small>Гости, которые ушли или не пришли из-за лагов, высокого пинга или нестабильной связи.</small></div>
    <div class="calc__row"><label for="c-cost">VELIQ за ПК в месяц, ₽</label><input class="input" id="c-cost" data-k="cost" inputmode="numeric" value="{PRICES['club_pc_month'] or 0}"><input type="range" data-k="cost" min="0" max="1000" step="10" value="{PRICES['club_pc_month'] or 0}" aria-label="Стоимость VELIQ"><small>{'Цена тарифа «Клуб».' if PRICES['club_pc_month'] else 'Цена тарифа ещё не объявлена — подставьте свою оценку.'}</small></div>
  </div>
  <div class="calc__out" aria-live="polite">
    <div><div style="color:var(--c-ink-300);margin-bottom:10px">Возвращённая выручка в месяц</div><div class="calc__big" data-out="net">—</div></div>
    <dl class="calc__lines">
      <div><dt>Оплаченных часов в месяц</dt><dd data-out="hours">—</dd></div>
      <div><dt>Выручка за часы</dt><dd data-out="revenue">—</dd></div>
      <div><dt>Возвращается с VELIQ</dt><dd data-out="back">—</dd></div>
      <div><dt>Стоимость VELIQ</dt><dd data-out="cost">—</dd></div>
    </dl>
    <p class="calc__formula">Расчёт: ПК × часы × 30 дней × загрузка × цена часа × доля потерянных часов − стоимость VELIQ. Это оценка по вашим цифрам, а не обещание дохода.</p>
  </div>
</div>
"""
clubs_body = f"""
<section class="page-head">
  <div class="wrap">
    <div class="crumbs"><a href="index.html">Главная</a> / Клубам</div>
    <h1 class="h1" style="max-width:15ch">VELIQ для компьютерных клубов</h1>
    <p class="lede">Гости приходят играть, общаться в голосовых чатах и смотреть стримы между матчами. Когда игра лагает или связь рвётся, они уходят туда, где всё в порядке.</p>
    <div class="hero__actions" style="margin-top:32px"><a class="btn btn--lg" href="#apply">Оставить заявку</a><a class="btn btn--lg btn--ghost" href="#calc">Посчитать выгоду</a></div>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <div class="sec__head"><h2 class="h2">Что теряет клуб</h2><p>Каждая такая ситуация — гость, который сегодня ушёл раньше, а завтра выбрал другой клуб.</p></div>
    <ol class="pains">
      <li><span class="pains__n">01</span><h3 class="h3">Связь рвётся</h3><p>Голосовой чат прерывается, стрим подвисает, обновление игры качается часами — команде неуютно.</p></li>
      <li><span class="pains__n">02</span><h3 class="h3">Игры лагают</h3><p>Высокий пинг и потери до игрового сервера — команда доигрывает и уходит туда, где играется лучше.</p></li>
      <li><span class="pains__n">03</span><h3 class="h3">Администратор занят не тем</h3><p>Смена уходит на «почему не работает», а не на гостей.</p></li>
    </ol>
  </div>
</section>

<section class="sec band--sunken">
  <div class="wrap">
    <div class="sec__head"><h2 class="h2">Что меняется с VELIQ</h2><p>Одна программа на каждом ПК — и маршруты строятся сами.</p></div>
    <div class="facts">
      <div class="fact"><h3>Гостю ничего не нужно делать</h3><p>VELIQ настраивается один раз, дальше гость просто садится и играет.</p></div>
      <div class="fact fact--r"><h3>Надёжно в клубе</h3><p>Гость не может изменить настройки или навредить программе.</p></div>
      <div class="fact"><h3>Лучший путь для игр</h3><p>VELIQ выбирает самый быстрый маршрут до игрового сервера и перестраивает его, если путь стал хуже.</p></div>
      <div class="fact fact--r"><h3>Стабильная связь</h3><p>Голосовые чаты и стримы работают без обрывов — у гостя ничего не нужно настраивать.</p></div>
    </div>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <div class="sec__head"><h2 class="h2">Кто что делает</h2><p>Вся настройка — один раз и у администратора. Гость просто садится играть.</p></div>
    <div class="roles">
      <div class="roles__col">
        <div class="roles__who">{icon('settings')}<h3 class="h3">Администратор</h3></div>
        <ul class="roles__list">
          <li>Устанавливает VELIQ и вводит код активации клуба</li>
          <li>Если что-то не так — пишет нам, поможем</li>
        </ul>
      </div>
      <div class="roles__col roles__col--guest">
        <div class="roles__who">{icon('games')}<h3 class="h3">Гость</h3></div>
        <ul class="roles__list">
          <li>Садится за ПК — VELIQ уже работает</li>
          <li>Видит только, что VELIQ работает</li>
          <li>Не может изменить настройки или что-то сломать</li>
        </ul>
      </div>
    </div>
  </div>
</section>

<section class="sec band--sunken" id="setup">
  <div class="wrap cols">
    <div>
      <h2 class="h2" style="margin-bottom:var(--sp-6)">Как подключить клуб</h2>
      <ol class="olist">
        <li><div><h3>Получите код активации</h3><p>Для клуба он выдаётся после заявки. Вместе с кодом вы получите инструкцию для клуба.</p></div></li>
        <li><div><h3>Установите VELIQ</h3><p>Установщик сам сделает всё нужное, дополнительных шагов не требуется.</p></div></li>
        <li><div><h3>Введите код активации</h3><p>После этого VELIQ готов к работе.</p></div></li>
      </ol>
      <p class="install-more">Подробные инструкции и ответы на частые вопросы скоро появятся в вики VELIQ.</p>
    </div>
    <aside class="aside">
      <div class="note">{icon('info')}<div><strong>Нужна помощь?</strong> Напишите на <a href="mailto:{SITE['email']}">{SITE['email']}</a> — расскажем, как подключить клуб, и пришлём код активации.</div></div>
    </aside>
  </div>
</section>

<section class="sec" id="calc">
  <div class="wrap">
    <div class="sec__head"><h2 class="h2">Сколько часов возвращает VELIQ</h2><p>Подставьте цифры своего клуба. Все значения можно менять.</p></div>
    {club_calc}
  </div>
</section>

<section class="sec band--ink" id="apply">
  <div class="wrap club-band">
    <div>
      <h2 class="h2">Поставим на один ПК — решите по факту</h2>
      <p class="lede" style="margin-top:20px">Напишите, сколько у вас компьютеров и какая система управления. Пришлём код активации и поможем с первой установкой.</p>
      <div class="hero__actions" style="margin-top:32px"><a class="btn btn--lg" href="mailto:{SITE['email']}?subject=VELIQ%20для%20клуба">Оставить заявку</a><a class="btn btn--lg btn--ghost" href="pricing.html">Тарифы</a></div>
    </div>
    <div class="club-band__pcs" aria-hidden="true">{''.join('<i></i>' for _ in range(27))}</div>
  </div>
</section>

<section class="sec">
  <div class="wrap">
    <div class="sec__head"><h2 class="h2">Вопросы владельцев клубов</h2><p>Презентацию и инструкцию для клуба пришлём по запросу.</p></div>
    <div class="faq">{faq(CLUB_FAQ)}</div>
  </div>
</section>
"""
page("clubs.html", "VELIQ для компьютерных клубов",
     "Быстрый путь для игр и стабильная связь на всех ПК клуба. Калькулятор выгоды.",
     "clubs", clubs_body, og="og-clubs.png", og_alt="VELIQ для компьютерных клубов: каждый ПК — работает.")

# ---------------------------------------------------------------- цены
BUY_URL = ACCOUNT_URL or f"mailto:{SITE['email']}?subject=Подписка%20VELIQ"
PRICE_NOTE = "" if PRICES_READY and SELLER_READY else f'<div class="note note--draft" style="margin-bottom:var(--sp-6)">{icon('info')}<div><strong>Цены готовятся.</strong> Числа появятся здесь перед началом продаж.</div></div>'
pricing_body = f"""
<section class="page-head">
  <div class="wrap">
    <div class="crumbs"><a href="index.html">Главная</a> / Цены</div>
    <h1 class="h1">Цены</h1>
    <p class="lede">Подписка на месяц. Платите за число компьютеров, на которых работает VELIQ.</p>
  </div>
</section>
<section class="sec sec--tight">
  <div class="wrap">
    {PRICE_NOTE}
    <div class="plans">
      <div class="plan">
        <h2 class="h3">Игрок</h2>
        <div class="plan__price">{rub(PRICES['player_month'])} <small>в месяц</small></div>
        <p class="muted" style="margin:0">Один компьютер дома.</p>
        <ul><li>{icon('check')}Самый быстрый путь для игр</li><li>{icon('check')}Стабильная связь для голосовых чатов и стримов</li><li>{icon('check')}Собственная сеть серверов</li><li>{icon('check')}Автопродление, отключается в один клик</li></ul>
        <a class="btn btn--ghost" href="{BUY_URL}">Оформить подписку</a>
      </div>
      <div class="plan plan--main">
        <h2 class="h3">Клуб</h2>
        <div class="plan__price">{rub(PRICES['club_pc_month'])} <small>за ПК в месяц</small></div>
        <p class="muted" style="margin:0">Для компьютерных клубов.</p>
        <ul><li>{icon('check')}Всё из тарифа «Игрок»</li><li>{icon('check')}Один код активации на все ПК клуба</li><li>{icon('check')}Гость не может изменить настройки</li><li>{icon('check')}Оплата картой или по счёту</li><li>{icon('check')}Помощь с установкой</li></ul>
        <a class="btn" href="mailto:{SITE['email']}?subject=Тариф%20Клуб">Оставить заявку</a>
      </div>
      <div class="plan">
        <h2 class="h3">Сеть клубов</h2>
        <div class="plan__price">по договору</div>
        <p class="muted" style="margin:0">Несколько адресов, свои условия.</p>
        <ul><li>{icon('check')}Всё из тарифа «Клуб»</li><li>{icon('check')}Условия под количество адресов</li></ul>
        <a class="btn btn--ghost" href="mailto:{SITE['email']}?subject=Сеть%20клубов">Написать нам</a>
      </div>
    </div>
    <p class="faint" style="font-size:var(--fs-sm);margin:var(--sp-4) 0 0">Цены в рублях, НДС не облагается.{" Продавец: " + seller_line() + "." if seller_line() else ""} Полные условия — в <a href="terms.html">публичной оферте</a>.</p>
  </div>
</section>
<section class="sec band--sunken" id="pay">
  <div class="wrap cols">
    <div class="prose">
      <h2 style="margin-top:0">Как оплатить</h2>
      <ol>
        <li>Войдите в личный кабинет по адресу электронной почты — пароль не нужен, придёт код.</li>
        <li>Выберите тариф и число компьютеров.</li>
        <li>Оплатите банковской картой (Мир, Visa, Mastercard) или через СБП. Чек придёт на почту.</li>
        <li>Скопируйте код активации из кабинета и введите его в программе.</li>
      </ol>
      <p>Клубам выставляем счёт: оплата с расчётного счёта организации или ИП, закрывающие документы — по запросу.</p>
      <h2 id="renew">Автопродление</h2>
      <p>Подписка продлевается в последний день оплаченного периода по цене тарифа. За день до списания пришлём письмо. Отключить автопродление можно в личном кабинете в любой момент — доступ сохранится до конца оплаченного периода.</p>
      <h2 id="refund">Возврат</h2>
      <p>Если VELIQ не заработал на вашем компьютере, вернём деньги полностью в течение 14 дней после первой оплаты. Позже — за неиспользованные полные дни, если вы отказываетесь от подписки. Напишите на <a href="mailto:{SITE['email']}">{SITE['email']}</a>; деньги вернутся тем же способом, которым вы платили, обычно в течение 10 дней.</p>
    </div>
    <aside class="aside">
      <div class="note">{icon('lock')}<div><strong>Безопасная оплата.</strong> Платёж проходит на защищённой странице платёжного сервиса {PAYMENT_AGENT}. Данные карты VELIQ не получает и не хранит.</div></div>
    </aside>
  </div>
</section>
"""
page("pricing.html", "Цены", "Тарифы VELIQ для игроков и компьютерных клубов, оплата, автопродление и возврат.", "pricing", pricing_body)

# ---------------------------------------------------------------- поддержка
ERRORS = [
    ("VELIQ не может запуститься", "Программа не может начать работу.", "Закройте VELIQ и откройте заново. Если не помогло — переустановите VELIQ или напишите нам."),
    ("Нет связи с сервером", "Серверы VELIQ не отвечают с вашего подключения.", "Проверьте, что интернет работает без VELIQ. Затем нажмите «Повторить» — программа попробует другой сервер. Если не помогло, напишите нам: возможно, провайдер блокирует соединение."),
    ("Часть сайтов не открывается", "Для сайтов маршрут пока не построен, а приложения работают.", "Нажмите «Повторить». Если компьютером управляет организация (рабочий компьютер), её правила могут запрещать изменения — тогда маршруты работают только для приложений."),
    ("Код активации не принят", "Сервер не принял код активации для этого устройства.", "Введите код ещё раз. Если не помогло — напишите нам."),
    ("Не хватает прав", "Действие требует прав администратора.", "Подтвердите запрос Windows."),
]
# Постоянные адреса ошибок: support.html#err-<ключ>. Ключи совпадают с кодами ошибок в app-ui/app.js — программа может открывать нужный ответ.
ERR_IDS = ["service", "relay", "browser", "identity", "rights"]
err_html = "\n".join(
    f'<details id="err-{k}"><summary>{t}{icon("chevron-down")}</summary><div class="a"><p><strong>Что случилось.</strong> {w}</p><p><strong>Что сделать.</strong> {f}</p></div></details>'
    for k, (t, w, f) in zip(ERR_IDS, ERRORS))
SUPPORT_FAQ = FAQ_MAIN + [
    ("Как выключить VELIQ?", "<p>Нажмите большую кнопку ещё раз. Интернет продолжит работать как без программы.</p>"),
    ("Как добавить свой сайт или приложение?", "<p>Вкладка «Сервисы» → «Добавить». VELIQ подберёт для него маршрут так же, как для остальных.</p>"),
]
support_body = f"""
<section class="page-head">
  <div class="wrap">
    <div class="crumbs"><a href="index.html">Главная</a> / Помощь</div>
    <h1 class="h1">Помощь</h1>
    <p class="lede">Ответы на частые вопросы и что делать при каждой ошибке, которую показывает программа.</p>
  </div>
</section>
<section class="sec sec--tight">
  <div class="wrap cols">
    <div>
      <div class="faq">
        <h2 class="faq__group">Общие вопросы</h2>
{faq(SUPPORT_FAQ)}
        <h2 class="faq__group" id="errors">Ошибки в программе</h2>
{err_html}
      </div>
    </div>
    <aside class="aside">
      <div class="card">
        <h2 class="h3" style="margin-bottom:10px">Не помогло?</h2>
        <p class="muted" style="margin:0 0 16px;font-size:var(--fs-sm)">Напишите нам, что случилось, — поможем.</p>
        <a class="btn btn--sm" href="mailto:{SITE['email']}?subject=Помощь%20VELIQ">{SITE['email']}</a>
      </div>
    </aside>
  </div>
</section>
"""
page("support.html", "Помощь и частые вопросы", "Ответы на вопросы о VELIQ и решения для каждой ошибки программы.", "support", support_body,
     {"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": [
         {"@type": "Question", "name": q, "acceptedAnswer": {"@type": "Answer", "text": a.replace("<p>", "").replace("</p>", "")}} for q, a in SUPPORT_FAQ]})

# ---------------------------------------------------------------- правовые
DRAFT = "" if SELLER_READY and LOG_RETENTION else f'<div class="note note--draft" style="margin-bottom:var(--sp-6)">{icon("alert")}<div><strong>Черновик.</strong> Реквизиты продавца и сроки хранения данных будут указаны перед началом продаж.</div></div>'
RETENTION = LOG_RETENTION or "[срок будет указан]"
SELLER_BLOCK = f"""<ul>
<li>Продавец: {SELLER['name'] or '[ФИО будет указано]'}</li>
<li>Статус: {SELLER['status']}</li>
<li>ИНН: {SELLER['inn'] or '[будет указан]'}</li>
<li>Электронная почта: <a href="mailto:{SELLER['email']}">{SELLER['email']}</a></li>
{f"<li>Телефон: {SELLER['phone']}</li>" if SELLER['phone'] else ""}
</ul>"""

privacy_body = f"""
<section class="page-head"><div class="wrap"><div class="crumbs"><a href="index.html">Главная</a> / Конфиденциальность</div><h1 class="h1">Политика конфиденциальности</h1><p class="lede">Какие данные получает VELIQ, зачем и сколько их хранит. Редакция от {OFFER_DATE}.</p></div></section>
<section class="sec sec--tight"><div class="wrap prose">
{DRAFT}
<h2>Коротко</h2>
<p>VELIQ направляет часть соединений через свои серверы, когда так быстрее или стабильнее. <strong>Мы не расшифровываем и не подменяем HTTPS</strong>: содержимое страниц, пароли и переписка серверу не видны. Мы собираем только то, без чего сервис не работает, и не продаём данные.</p>
<h2>1. Кто обрабатывает данные</h2>
<p>Оператор персональных данных — продавец сервиса VELIQ:</p>
{SELLER_BLOCK}
<p>Политика составлена в соответствии с Федеральным законом от 27.07.2006 № 152-ФЗ «О персональных данных».</p>
<h2>2. Какие данные и зачем</h2>
<ul>
<li><strong>Адрес электронной почты</strong> — чтобы вы могли войти в личный кабинет, получать чеки и письма о подписке.</li>
<li><strong>Данные о подписке и платежах</strong>: тариф, число компьютеров, срок, сумма и статус платежа — чтобы предоставлять оплаченный доступ и выполнять требования налогового учёта.</li>
<li><strong>Данные устройства</strong>: ключ устройства, обезличенный идентификатор компьютера (необратимый хеш), версия программы, время последнего подключения — чтобы пускать на серверы только активированные копии VELIQ и считать занятые места.</li>
<li><strong>Технические данные соединений</strong>, которые проходят через серверы VELIQ: адрес и порт назначения, имя сайта из начала соединения, объём данных и время — чтобы переслать трафик и защитить серверы от злоупотреблений.</li>
<li><strong>Обращения в поддержку</strong> и отчёты диагностики, если вы сами их прислали.</li>
</ul>
<p>Данные банковской карты получает и обрабатывает платёжный сервис {PAYMENT_AGENT}. VELIQ их не получает и не хранит.</p>
<h2>3. Основания</h2>
<p>Данные обрабатываются для заключения и исполнения договора, в котором вы — сторона (п. 5 ч. 1 ст. 6 152-ФЗ), и для исполнения требований закона (налоговый учёт, чеки).</p>
<h2>4. Сроки хранения</h2>
<ul>
<li>Аккаунт и данные подписки — пока аккаунт существует и ещё 3 года после его удаления (налоговый учёт).</li>
<li>Журналы соединений на серверах — {RETENTION}.</li>
<li>Обращения в поддержку — 1 год.</li>
</ul>
<h2>5. Кому передаём</h2>
<p>Только тем, без кого сервис не работает: платёжному сервису — для приёма оплаты, почтовому сервису — для отправки писем, хостинг-провайдерам — на их оборудовании работают серверы VELIQ. Часть серверов может находиться за пределами России. Мы не продаём данные и не передаём их рекламным сетям. Данные раскрываются государственным органам только в случаях, прямо предусмотренных законом.</p>
<h2>6. Ваши права</h2>
<p>Вы можете узнать, какие ваши данные мы храним, исправить их или потребовать удалить аккаунт — напишите на <a href="mailto:{SITE['email']}">{SITE['email']}</a> с адреса, к которому привязан аккаунт. Ответим в течение 10 рабочих дней. Удаление аккаунта прекращает подписку.</p>
<h2>7. Что остаётся на компьютере</h2>
<p>Настройки, список сервисов и журнал диагностики хранятся только на вашем компьютере. Отчёт диагностики мы получаем, только если вы сами его пришлёте.</p>
<h2>8. Сайт и cookie</h2>
<p>Сайт не использует счётчики и рекламные cookie. Выбор темы сохраняется только в вашем браузере. Личный кабинет использует одну служебную cookie, чтобы вы оставались в нём после входа.</p>
<h2>9. Изменения</h2>
<p>Новая редакция публикуется на этой странице с датой. Если изменения существенные, сообщим письмом.</p>
</div></section>
"""
page("privacy.html", "Политика конфиденциальности", "Какие данные получает VELIQ, зачем и сколько хранит. HTTPS не расшифровывается, данные не продаются.", "", privacy_body)

terms_body = f"""
<section class="page-head"><div class="wrap"><div class="crumbs"><a href="index.html">Главная</a> / Оферта</div><h1 class="h1">Публичная оферта</h1><p class="lede">Договор на предоставление доступа к сервису VELIQ. Редакция от {OFFER_DATE}.</p></div></section>
<section class="sec sec--tight"><div class="wrap prose">
{DRAFT}
<p>{SELLER['name'] or '[ФИО продавца]'}, {SELLER['status']}, ИНН {SELLER['inn'] or '[ИНН]'} (далее — Исполнитель), предлагает любому лицу (далее — Пользователь) заключить договор на условиях ниже. Это публичная оферта по ст. 437 Гражданского кодекса РФ.</p>
<h2>1. Термины</h2>
<ul>
<li><strong>Сервис</strong> — программа VELIQ для Windows и серверы Исполнителя. Программа выбирает маршрут для сетевых соединений компьютера — через серверы Исполнителя или обычным путём — чтобы снизить задержку и повысить стабильность соединений в онлайн-играх и других онлайн-сервисах.</li>
<li><strong>Подписка</strong> — оплаченный доступ к Сервису на определённый срок для определённого числа компьютеров (мест).</li>
<li><strong>Личный кабинет</strong> — раздел сайта {SITE['url']}, где Пользователь управляет подпиской, местами и оплатой.</li>
<li><strong>Код активации</strong> — код, который связывает компьютер с подпиской.</li>
</ul>
<h2>2. Предмет договора</h2>
<p>Исполнитель предоставляет Пользователю доступ к Сервису на срок Подписки и для числа компьютеров, указанных в выбранном тарифе, а Пользователь оплачивает его. Программа предоставляется по простой неисключительной лицензии на срок Подписки.</p>
<h2>3. Акцепт</h2>
<p>Оплата Подписки означает полное и безоговорочное принятие этой оферты (п. 3 ст. 438 ГК РФ). Договор действует до окончания оплаченного периода и продлевается при каждой следующей оплате.</p>
<h2>4. Стоимость и оплата</h2>
<ul>
<li>Цены указаны на странице <a href="pricing.html">«Цены»</a> в рублях. НДС не облагается: Исполнитель применяет налог на профессиональный доход.</li>
<li>Оплата — банковской картой или через СБП на платёжной странице {PAYMENT_AGENT}, либо по счёту для организаций и ИП.</li>
<li>После оплаты Исполнитель формирует чек в приложении «Мой налог» и направляет его на электронную почту Пользователя.</li>
<li>Изменение цен не затрагивает уже оплаченный период. О новой цене для автопродления сообщим письмом не позднее чем за 7 дней.</li>
</ul>
<h2>5. Автопродление</h2>
<ul>
<li>Если при оплате Пользователь включил автопродление, Подписка продлевается на следующий период списанием с сохранённого способа оплаты в последний день оплаченного периода.</li>
<li>За 1 день до списания Исполнитель направляет письмо с суммой и датой.</li>
<li>Автопродление отключается в Личном кабинете в любой момент; доступ сохраняется до конца оплаченного периода.</li>
<li>Если списание не прошло, Исполнитель может повторить его в течение 3 дней. После этого доступ приостанавливается до оплаты.</li>
</ul>
<h2>6. Как предоставляется доступ</h2>
<ul>
<li>Доступ открывается сразу после поступления оплаты: в Личном кабинете появляется Код активации.</li>
<li>Пользователь сам освобождает места в Личном кабинете, если меняет компьютер.</li>
<li>Когда Подписка закончилась, программа перестаёт использовать серверы Исполнителя и оптимизировать соединения. Интернет на компьютере продолжает работать как без программы.</li>
<li>Исполнитель может проводить плановые работы на серверах, по возможности заранее предупреждая о них.</li>
</ul>
<h2>7. Возврат</h2>
<ul>
<li>Если Сервис не заработал на компьютере Пользователя, Исполнитель возвращает оплату полностью по заявке, направленной в течение 14 дней после первой оплаты.</li>
<li>Пользователь может отказаться от Подписки в любой момент; Исполнитель возвращает оплату за неиспользованные полные дни (ст. 32 Закона РФ «О защите прав потребителей»).</li>
<li>Заявка — на <a href="mailto:{SITE['email']}">{SITE['email']}</a> с адреса, к которому привязан аккаунт. Деньги возвращаются тем же способом, которым была оплата, в течение 10 рабочих дней.</li>
</ul>
<h2>8. Правила использования</h2>
<ul>
<li>Пользователь обязуется соблюдать законодательство РФ и не использовать Сервис для рассылки спама, атак на сети и сервисы, распространения вредоносных программ, мошенничества и иных противоправных действий.</li>
<li>Нельзя передавать Код активации третьим лицам сверх оплаченного числа мест, перепродавать доступ, изучать или изменять программу в обход её защиты.</li>
<li>При нарушении Исполнитель вправе приостановить доступ, предварительно уведомив Пользователя по электронной почте, если нарушение не требует немедленной остановки.</li>
</ul>
<h2>9. Ответственность</h2>
<ul>
<li>Исполнитель отвечает за работу своих серверов и программы. Работа сторонних сайтов, игр, игровых серверов и интернет-провайдера от Исполнителя не зависит.</li>
<li>Снижение задержки зависит от провайдера и расположения игрового сервера; Исполнитель не гарантирует конкретное значение пинга.</li>
<li>Если доступ к Сервису отсутствовал по вине Исполнителя более 24 часов подряд, срок Подписки продлевается на это время по заявке Пользователя.</li>
<li>Ответственность Исполнителя ограничена суммой, уплаченной за текущий период, кроме случаев, когда ограничение запрещено законом.</li>
</ul>
<h2>10. Персональные данные</h2>
<p>Исполнитель обрабатывает данные Пользователя по <a href="privacy.html">политике конфиденциальности</a>. Принимая оферту, Пользователь соглашается с ней.</p>
<h2>11. Изменение оферты и споры</h2>
<p>Новая редакция публикуется на этой странице и действует для новых оплат. Споры решаются переговорами; претензию нужно направить на электронную почту, ответ — в течение 10 рабочих дней. Если договориться не удалось — в суде по законодательству РФ.</p>
<h2>12. Реквизиты Исполнителя</h2>
{SELLER_BLOCK}
</div></section>
"""
page("terms.html", "Публичная оферта", "Условия предоставления доступа к VELIQ: оплата, автопродление, возврат, ответственность.", "", terms_body)

contacts_body = f"""
<section class="page-head"><div class="wrap"><div class="crumbs"><a href="index.html">Главная</a> / Контакты</div><h1 class="h1">Контакты и реквизиты</h1><p class="lede">Как с нами связаться и кто продаёт VELIQ.</p></div></section>
<section class="sec sec--tight"><div class="wrap cols">
  <div class="prose">
    {DRAFT if not SELLER_READY else ""}
    <h2>Связь</h2>
    <p>Поддержка, вопросы об оплате и возврате, заявки клубов — <a href="mailto:{SITE['email']}">{SITE['email']}</a>{f", {SELLER['phone']}" if SELLER['phone'] else ""}. Отвечаем в течение рабочего дня.</p>
    <h2>Реквизиты</h2>
    {SELLER_BLOCK}
    <p>Документы: <a href="terms.html">публичная оферта</a>, <a href="privacy.html">политика конфиденциальности</a>, <a href="pricing.html#refund">условия возврата</a>.</p>
  </div>
  <aside class="aside">
    <div class="card">
      <h2 class="h3" style="margin-bottom:10px">Нужна помощь с программой?</h2>
      <p class="muted" style="margin:0 0 16px;font-size:var(--fs-sm)">Ответы на частые вопросы и решения ошибок — на странице помощи.</p>
      <a class="btn btn--sm btn--ghost" href="support.html">Помощь</a>
    </div>
  </aside>
</div></section>
"""
page("contacts.html", "Контакты и реквизиты", "Контакты поддержки VELIQ и реквизиты продавца.", "", contacts_body)

# ---------------------------------------------------------------- личный кабинет
# Разметку оживляет assets/account.js; API — /api/v1/account на том же домене (docs/ACCOUNTS.md).
account_body = f"""
<section class="page-head"><div class="wrap"><div class="crumbs"><a href="index.html">Главная</a> / Личный кабинет</div><h1 class="h1">Личный кабинет</h1><p class="lede">Подписка, оплата и коды активации — в одном месте.</p></div></section>
<section class="sec sec--tight"><div class="wrap" data-account>
  <div data-step="email">
    <form class="acc-form" data-email-form novalidate>
      <label class="field"><span>Почта</span><input class="input" type="email" name="email" autocomplete="email" required placeholder="you@example.ru"></label>
      <button class="btn" type="submit">Получить код для входа</button>
      <p class="acc-error" data-email-error hidden></p>
      <p class="muted acc-small">Пароль не нужен: пришлём на почту код из шести цифр. Входя, вы принимаете <a href="terms.html">оферту</a> и <a href="privacy.html">политику конфиденциальности</a>.</p>
    </form>
  </div>
  <div data-step="code" hidden>
    <form class="acc-form" data-code-form novalidate>
      <p>Код отправлен на <b data-sent-to></b>. Письмо может прийти через минуту, проверьте и «Спам».</p>
      <label class="field"><span>Код из письма</span><input class="input mono" type="text" name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="6" required></label>
      <button class="btn" type="submit">Войти</button>
      <button class="btn btn--quiet btn--sm" type="button" data-change-email>Другая почта</button>
      <p class="acc-error" data-code-error hidden></p>
    </form>
  </div>
  <div data-step="cabinet" hidden>
    <div class="acc-head"><p class="muted" style="margin:0">Вы вошли как <b data-account-email></b></p><button class="btn btn--ghost btn--sm" type="button" data-logout>Выйти</button></div>
    <h2 class="h2">Подписки</h2>
    <p class="muted" data-subs-empty>Подписок пока нет. Выберите тариф ниже.</p>
    <div class="acc-subs" data-subs></div>
    <h2 class="h2">Оформить подписку</h2>
    <div class="acc-plans" data-plans></div>
    <h2 class="h2">Платежи</h2>
    <p class="muted" data-payments-empty>Платежей пока не было.</p>
    <ul class="acc-pays" data-payments></ul>
    <p class="muted acc-small">Вопросы об оплате и возврате — <a href="mailto:{SITE['email']}">{SITE['email']}</a>. Условия — в <a href="pricing.html#refund">разделе о возврате</a>.</p>
  </div>
</div></section>
<script src="assets/account.js"></script>
"""
page("account.html", "Личный кабинет", "Вход в личный кабинет VELIQ: подписка, оплата, коды активации.", "", account_body)

nf_body = f"""
<section class="center-stack"><div class="wrap">
  <h1 class="h-display"><span class="slit-line" style="margin:0 auto"><span class="slit">404</span></span></h1>
  <p class="lede" style="margin:24px auto 32px">Такой страницы нет. Возможно, её перенесли.</p>
  <a class="btn btn--lg" href="index.html">На главную</a>
</div></section>
"""
page("404.html", "Страница не найдена", "Страница не найдена.", "", nf_body)

# ---------------------------------------------------------------- план развития
# Публичная версия docs/ROADMAP.md: без адресов серверов, кодов, внутренних сроков и названий клубов.
# Статусы менять здесь вместе с docs/ROADMAP.md и запускать генератор.
ROADMAP_UPDATED = "25 октября 2026"
# Тексты — по правилам brand/copy.md: без адресов и расположения серверов, без названий игр и сторонних систем,
# без «образа», без непроверенных обещаний (качество видео, сроки). Сервисы — только как примеры.
ROADMAP = [
    ("done", "Готово", "Работает в бета-версии", [
        "Стабильная связь для онлайн-сервисов через собственную сеть серверов VELIQ",
        "Стримы и видео в высоком качестве без подвисаний",
        "Обычные сайты идут как обычно, без лишних задержек",
        "Ничего не нужно перезапускать: маршруты подхватываются сразу",
        "Собственные серверы с быстрым каналом",
    ]),
    ("now", "Сейчас", "Делаем сейчас", [
        "Оптимизация соединений прямо на компьютере, без сервера — быстрее и стабильнее",
        "Игры: оптимальный маршрут и проверка в реальных матчах",
        "Автоматическое переключение на резервный сервер",
        "Установщик одним файлом",
    ]),
    ("next", "Дальше", "Следующие шаги", [
        "Версия для клубов: один код активации на все компьютеры клуба",
        "Пилот в компьютерном клубе",
        "Личный кабинет и оплата онлайн",
        "Версия для телефона",
    ]),
]
RM_ICON = {"done": "check", "now": "refresh", "next": "route"}
roadmap_stages = "\n".join(
    f'''      <li class="rm__stage rm__stage--{key}">
        <div class="rm__track" aria-hidden="true"><span class="rm__node">{icon(RM_ICON[key])}</span><span class="rm__line"></span></div>
        <div class="rm__card">
          <span class="rm__label">{label}</span>
          <h2 class="h3">{title}</h2>
          <ul class="rm__list">{"".join(f"<li>{item}</li>" for item in items)}</ul>
        </div>
      </li>'''
    for key, label, title, items in ROADMAP)
roadmap_body = f"""
<section class="page-head">
  <div class="wrap">
    <div class="crumbs"><a href="index.html">Главная</a> / План развития</div>
    <h1 class="h1">План развития</h1>
    <p class="lede">Что VELIQ уже умеет, над чем работаем сейчас и что будет дальше.</p>
  </div>
</section>
<section class="sec">
  <div class="wrap">
    <ol class="rm" data-trace aria-label="Этапы развития VELIQ">
{roadmap_stages}
    </ol>
    <div class="rm__foot">
      <p>Обновлено {ROADMAP_UPDATED}. Сроки не объявляем: пункт переходит в «Готово» только после проверки на реальных компьютерах и у реальных провайдеров.</p>
      <div class="hero__actions"><a class="btn btn--lg" href="download.html">{icon('download')}Скачать</a><a class="btn btn--lg btn--ghost" href="clubs.html">Для компьютерных клубов</a></div>
    </div>
  </div>
</section>
"""
page("roadmap.html", "План развития", "Что VELIQ уже умеет, над чем работаем сейчас и что будет дальше.", "", roadmap_body)

# ---------------------------------------------------------------- служебные файлы
pages = ["", "how.html", "download.html", "clubs.html", "pricing.html", "support.html", "privacy.html", "terms.html", "contacts.html", "roadmap.html"]
(OUT / "sitemap.xml").write_text(
    '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
    + "".join(f"  <url><loc>{SITE['url']}/{p}</loc></url>\n" for p in pages) + "</urlset>\n", encoding="utf-8")
(OUT / "robots.txt").write_text(f"User-agent: *\nAllow: /\nDisallow: /account.html\nDisallow: /api/\nSitemap: {SITE['url']}/sitemap.xml\n", encoding="utf-8")
(OUT / "site.webmanifest").write_text(json.dumps({
    "name": "VELIQ", "short_name": "VELIQ", "lang": "ru", "start_url": "index.html", "display": "browser",
    "background_color": "#0A0A0B", "theme_color": "#0A0A0B",
    "icons": [{"src": "assets/img/app-icon-192.png", "sizes": "192x192", "type": "image/png"},
              {"src": "assets/img/app-icon-512.png", "sizes": "512x512", "type": "image/png"}]}, ensure_ascii=False, indent=2), encoding="utf-8")
print("служебные файлы: sitemap.xml, robots.txt, site.webmanifest")
