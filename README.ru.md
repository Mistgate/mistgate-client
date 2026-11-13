<div align="center">

<img src="ui/src-tauri/icons/128x128.png" width="96" height="96" alt="Mistgate">

<h1>Mistgate для Windows</h1>

<p>VPN-приложение, которое само находит рабочий путь и честно говорит, когда что-то заблокировано.<br>
Hysteria2, AmneziaWG и VLESS в одном окне. Для панелей <a href="https://github.com/Mistgate/mistgate">Mistgate</a> и для обычных ссылок подписки.</p>

<p>
<img alt="beta" src="https://img.shields.io/badge/status-beta-f2c46b">
<a href="https://github.com/Mistgate/mistgate-client/releases/latest"><img alt="0.1.0" src="https://img.shields.io/badge/version-0.1.0-b8acf2"></a>
<a href="LICENSE"><img alt="AGPL-3.0" src="https://img.shields.io/github/license/Mistgate/mistgate-client?color=b8acf2"></a>
<img alt="Windows 10, 11 x64" src="https://img.shields.io/badge/Windows-10%20%7C%2011%20x64-8ec8ea">
<a href="core/go.mod"><img alt="Go" src="https://img.shields.io/github/go-mod/go-version/Mistgate/mistgate-client?filename=core%2Fgo.mod"></a>
<img alt="Tauri 2" src="https://img.shields.io/badge/Tauri-2-7dd3a0">
</p>

<p><a href="https://github.com/Mistgate/mistgate-client/releases/latest"><b>Скачать</b></a> · <a href="docs/build.md"><b>Сборка</b></a> · <a href="README.md">English</a> · <a href="README.zh.md">简体中文</a> · <a href="README.fa.md">فارسی</a> · <a href="README.tr.md">Türkçe</a></p>

<p><sub><b>Бета.</b> Версия 0.1, только Windows. До 1.0 возможны изменения.</sub></p>

</div>

<img alt="Главное окно: подключено, справа список серверов" src="docs/img/home.png" width="100%">

<p align="center"><sub>Картинки на этой странице — экраны приложения с образцовыми данными.</sub></p>

<div>

## Что умеет

Подписка добавляется один раз. Приложение само обновляет список серверов, подключается тем протоколом, который работает в вашей сети, и пускает через VPN только то, что вы хотите.

- **Одна кнопка, три протокола.** Hysteria2, AmneziaWG и VLESS. *Авто* берёт сервер, который отвечает быстрее всех прямо сейчас; сервер и протокол можно выбрать и самому.
- **С панелью Mistgate и без неё.** Вставьте ссылку подписки, ссылки `hysteria2://` или `vless://`, профиль Mihomo или конфиг AmneziaWG. С панелью Mistgate приложение регистрирует этот ПК своим ключом, следит за серверами панели и показывает тариф, трафик и устройства.
- **Маршруты.** *Умный* оставляет местные сайты и домашнюю сеть мимо VPN, *Только выбранное* пускает через VPN лишь то, что вы отметили, *Всё* — весь трафик. Правила по готовым подборкам, своим спискам, сайтам и программам.
- **Kill switch.** Пока туннель лежит, с ПК ничего не уходит: на время подключения или всегда.
- **Проверка сети.** Одна кнопка показывает, какие серверы и какие пути к ним работают отсюда.
- **Локальный прокси.** SOCKS5 и HTTP для программ и домашних устройств, которые не умеют в VPN сами.
- **Прокси для Telegram** из панели: одно нажатие передаёт прокси в Telegram.
- **Остальное.** Быстрая панель в трее, уведомления Windows, тёмная и светлая темы, пять языков: английский, русский, китайский, фарси, турецкий.
- **Обновления** из релизов этого репозитория. Приложение ставит только установщик, подписанный ключом проекта.

</div>

<table>
  <tr>
    <td width="50%"><img src="docs/img/routes.png" alt="Маршруты: что идёт через VPN, а что нет"></td>
    <td width="50%"><img src="docs/img/settings.png" alt="Настройки"></td>
  </tr>
  <tr>
    <td align="center"><sub>Маршруты: что идёт через VPN, а что нет</sub></td>
    <td align="center"><sub>Настройки</sub></td>
  </tr>
</table>

<div>

## Протоколы

| Протокол | В приложении | Что поддерживает |
|:--|:--|:--|
| Hysteria2 | Официальное ядро Hysteria2, встроено | UDP (QUIC). Обфускация Salamander, смена портов. |
| AmneziaWG | amneziawg-go, встроен | Версии 2.0 и 3.1, ключ на устройство из панели Mistgate или файл `.conf`. |
| VLESS | Xray-core, встроен | REALITY или TLS; RAW с Vision, XHTTP и WebSocket. |

Все три работают внутри одной службы Windows и одного адаптера wintun. Не поддерживаются: VMess, Trojan, Shadowsocks, TUIC и обычный WireGuard.

## Установка

<img align="right" src="docs/img/setup.png" alt="Установка" width="360">

Windows 10 или 11, x64.

1. Скачайте `MistgateSetup_<версия>_x64.exe` из [последнего релиза](https://github.com/Mistgate/mistgate-client/releases/latest) и запустите.
2. Windows один раз спросит права администратора: приложение ставит фоновую службу, которая держит туннель.
3. Вставьте ссылку подписки и нажмите большую кнопку.

У установщика пока нет сертификата подписи кода Windows, поэтому SmartScreen может предупредить о неизвестном издателе. Обновления проверяются иначе, собственной подписью проекта: [как устроены обновления](docs/build.md#updates-of-the-installed-app).

<br clear="right">

## Приватность

- Ключи устройства и данные серверов лежат в хранилище, которое Windows шифрует для учётной записи службы.
- В журнале нет ключей, ссылок, адресов серверов, имён сайтов и программ.
- Приложение не сообщает панели, что вы открываете. Отладочный отчёт уходит с ПК только по вашей кнопке, и перед отправкой приложение показывает его построчно.

## Состояние

Это бета, проект молодой. Пока нет: сертификата подписи кода Windows, своего экрана удаления, сборок для macOS и Linux. Если что-то не работает, [создайте issue](https://github.com/Mistgate/mistgate-client/issues). Как собрать самому: [docs/build.md](docs/build.md).

## Лицензия

[AGPL-3.0](LICENSE). У встроенных библиотек свои лицензии, среди них Xray-core (MPL-2.0), Hysteria, amneziawg-go, gVisor и wintun.

</div>
