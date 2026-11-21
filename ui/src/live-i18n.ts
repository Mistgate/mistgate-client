// The words Home needs around real numbers and dates. The wording is the design's (its sample subscriptions in each
// language); here it is turned into patterns. ponytail: tr, zh and fa follow the design's samples but were not read
// by a native speaker.
type KeepCode = 'offline' | 'fetch_failed' | 'unsupported_format';
type AddCode = 'offline' | 'service_down' | 'timeout' | 'insecure_link' | 'no_servers' | 'unsupported_format' | 'service_error';
type Words = {
  locale: string;
  days: (n: number) => string;
  left: (days: string) => string;
  until: (date: string) => string;
  lifetime: string;
  noEnd: string;
  noCert: string; // a server whose certificate the subscription asks not to check: the mark on its row, and in full
  noCertFull: string;
  wl: [title: string, answers: string, silent: string]; // the channel for allowlists in the diagnostics table
  trayMenu: [open: string, quit: string]; // the tray icon's menu, in the design's words
  noEndCap: string;
  expired: string;
  expiredOn: (date: string) => string;
  expiredMeta: (date: string) => string;
  servers: (n: number) => string;
  gb: string;
  leftOf: (total: string) => string;
  used: string;
  renew: string;
  link: string;
  file: string;
  stale: (time: string, why?: string) => string; // why: the service's code in words (keep); none: a generic failure
  validUntil: string;
  add: (servers: string) => string;
  dnsReplaced: string;
  dnsReplacedLine: (replaced: number, checked: number) => string;
  foreignCut: string;
  // why a subscription has stopped, by the service's code (inactive: by the panel's status)
  subErr: Record<string, string>;
  // why the last update failed while the saved copy goes on, by the service's code (the head of the "stale" line)
  keep: Record<KeepCode, string>;
  // the add sheet, for a link that failed with no words of the panel's own (they win), by the service's code
  addErr: Record<AddCode, string>;
  onlyKinds: (kinds: string) => string; // the add sheet, "no_servers": what the subscription holds instead
  // other VPNs and DPI-bypass tools running on this machine (the design has no row for them yet)
  neighbours: [name: string, verdict: string, meta: string];
  throttled: string; // the speed through the VPN falls after the first seconds
  diagFail: Record<string, [title: string, text: string]>; // why a network check did not run, by the service's code
  off: string; // a switch that is off, as a short state (the kill switch on the Routes screen)
  modes: [only: string, all: string, smart: string]; // the route modes on Home's chip, worded as on the Routes screen
  // the Routes test line, in the design's own words: the three verdicts, then why (%s: the rule's name)
  // Windows notifications, after the design's samples: a title and a text each
  notify: { lost: [string, string]; backup: [string, (way: string) => string]; ends: [(days: string, n: number) => string, (name: string, date: string) => string]; removed: [string, (name: string) => string] };
  // Diagnostics, the "ask for help" sheet: why the diagnostics were not sent
  dbg: { wait: (min: number) => string; offline: string; gone: string; full: string; fail: string; look: string };
  proxyBusy: string; // Settings, Local proxy: it could not listen
  synced: (time: string) => string; // Settings, Subscription: when it was last taken from the provider
  chk: [vpn: string, direct: string, blocked: string, all: string, on: string, notSelected: string, goesDirect: string, notException: string];
  lists: { region: (cc: string) => string; entries: (n: string) => string; updated: (time: string) => string; failed: string; checking: string }; // rows of the Lists sheet
};

const ruForm = (n: number, one: string, few: string, many: string) =>
  ({ one, few, many, other: many } as Record<string, string>)[new Intl.PluralRules('ru').select(n)];
const enForm = (n: number, one: string, other: string) => (n === 1 ? one : other);

const WORDS: Record<string, Words> = {
  en: {
    locale: 'en-US', wl: ["For allowlists","answers","no answer"], trayMenu: ["Open Mistgate", "Quit"], noCert: 'no cert check', noCertFull: 'certificate not checked', days: (n) => `${n} ${enForm(n, 'day', 'days')}`, left: (d) => `${d} left`, until: (d) => `until ${d}`,
    lifetime: 'Lifetime', noEnd: 'no end date', noEndCap: 'No end date', expired: 'Expired', expiredOn: (d) => `on ${d}`,
    expiredMeta: (d) => `expired ${d}`, servers: (n) => `${n} ${enForm(n, 'server', 'servers')}`, gb: 'GB',
    leftOf: (t) => `left of ${t}`, used: 'used · no cap', renew: 'renew to use', link: 'Link', file: 'File',
    stale: (t, why = 'Couldn’t update') => `${why} · using the copy from ${t}`, validUntil: 'valid until', add: (s) => `Add ${s}`,
    dnsReplaced: "Some site addresses are replaced on this network", dnsReplacedLine: (n, m) => `${n} of ${m} test sites got a replaced address`, foreignCut: "Some foreign sites are cut off on this network",
    subErr: {"device_removed":"This device was removed from the subscription · add the link again","device_blocked":"This device is blocked by the provider","link_changed":"The link was replaced · paste the new one","device_limit":"Device limit reached · remove a device on the subscription page","device_exists":"This device is already registered · remove it on the subscription page","app_disabled":"The app is switched off for this account · ask your provider","disabled":"The subscription is turned off by the provider","expired":"The subscription has expired","limited":"The traffic is used up","client_api_off":"This provider doesn’t allow the app for this subscription · ask your provider","user_inactive":"The subscription isn’t active · ask your provider","too_many_requests":"Too many requests · wait a few minutes and try again"},
    keep: {"offline":"No internet","fetch_failed":"The provider’s server didn’t answer","unsupported_format":"Update the app to read this subscription"},
    addErr: {"offline":"No internet connection. Connect to a network and try again","service_down":"Mistgate’s background service isn’t answering. Wait a moment and try again","timeout":"No answer in time. Try again in a minute","insecure_link":"A link without encryption (http) isn’t accepted. Ask for a link that starts with https","no_servers":"This subscription has no servers the app can use","unsupported_format":"The app can’t read this kind of subscription. Update the app or ask your provider for another link","service_error":"The app couldn’t add this. Try again, and restart Mistgate if it repeats"},
    onlyKinds: (k) => `The subscription has only protocols the app doesn’t support: ${k}`,
    neighbours: ["Other VPN programs","Found","They can break the connection: close them while Mistgate is on"],
    throttled: "Speed through the VPN falls after the first seconds",
    diagFail: { no_subscription: ["Nothing to check yet", "Add a subscription first: the check tests its servers"], offline: ["No internet", "Connect to a network and run the check again"] },
    off: 'off',
    modes: ['Only selected', 'Everything', 'Smart'],
    notify: { lost: ['Connection lost', 'No answer for 30 seconds. Mistgate keeps trying.'], backup: ['Switched to a backup way', (way) => `The previous way stopped answering, so Mistgate moved you to ${way}.`], ends: [(days) => `Subscription ends in ${days}`, (name, date) => `${name} ends on ${date}. Renew it to keep VPN working.`], removed: ['This PC was removed', (name) => `It’s no longer in ${name}, so VPN can’t connect.`] },
    dbg: { wait: (min) => `You can send again in ${min} min`, offline: 'No connection to your admin’s server. Try again later', gone: 'Your admin no longer waits for these diagnostics', full: 'Your admin’s storage for diagnostics is full. Tell them directly', fail: 'Couldn’t send. Try again later', look: 'This is what will be sent. Check it and press Send again' },
    proxyBusy: 'Couldn’t start · port 1080 or 8080 is used by another program',
    synced: (t) => `Updated ${t}`,
    chk: ['VPN', 'Direct', 'Blocked', 'Rule: Everything mode', 'Rule: “%s” is on', 'Rule: not in your selection', 'Rule: “%s” goes direct', 'Rule: not an exception'],
    lists: { region: (cc) => `Addresses of ${cc}`, entries: (n) => `${n} entries`, updated: (t) => `updated ${t}`, failed: 'Couldn’t update', checking: 'Checking the link…' },
  },
  ru: {
    locale: 'ru-RU', wl: ["Для белых списков","отвечает","не отвечает"], trayMenu: ["Открыть Mistgate", "Выход"], noCert: 'без проверки', noCertFull: 'без проверки сертификата', days: (n) => `${n} ${ruForm(n, 'день', 'дня', 'дней')}`, left: (d) => `осталось ${d}`, until: (d) => `до ${d}`,
    lifetime: 'Бессрочно', noEnd: 'бессрочно', noEndCap: 'Бессрочно', expired: 'Истекла', expiredOn: (d) => d,
    expiredMeta: (d) => `истекла ${d}`, servers: (n) => `${n} ${ruForm(n, 'сервер', 'сервера', 'серверов')}`, gb: 'ГБ',
    leftOf: (t) => `осталось из ${t}`, used: 'израсходовано · без лимита', renew: 'продлите, чтобы пользоваться', link: 'Ссылка', file: 'Файл',
    stale: (t, why = 'Не удалось обновить') => `${why} · используется копия от ${t}`, validUntil: 'действует до', add: (s) => `Добавить ${s}`,
    dnsReplaced: "В этой сети подменяют адреса некоторых сайтов", dnsReplacedLine: (n, m) => `Подменён адрес у ${n} из ${m} проверенных сайтов`, foreignCut: "Часть зарубежных сайтов в этой сети недоступна",
    subErr: {"device_removed":"Это устройство удалено из подписки · добавьте ссылку заново","device_blocked":"Это устройство заблокировано провайдером","link_changed":"Ссылку заменили · вставьте новую","device_limit":"Достигнут лимит устройств · удалите одно на странице подписки","device_exists":"Это устройство уже зарегистрировано · удалите его на странице подписки","app_disabled":"Приложение отключено для этого аккаунта · обратитесь к провайдеру","disabled":"Подписка отключена провайдером","expired":"Срок подписки истёк","limited":"Трафик израсходован","client_api_off":"Провайдер не разрешает приложение для этой подписки · обратитесь к нему","user_inactive":"Подписка не активна · обратитесь к провайдеру","too_many_requests":"Слишком много запросов · подождите несколько минут и повторите"},
    keep: {"offline":"Нет интернета","fetch_failed":"Сервер провайдера не ответил","unsupported_format":"Обновите приложение, чтобы читать эту подписку"},
    addErr: {"offline":"Нет интернета. Подключитесь к сети и повторите","service_down":"Служба Mistgate не отвечает. Подождите немного и повторите","timeout":"Ответ не пришёл вовремя. Повторите через минуту","insecure_link":"Ссылка без шифрования (http) не принимается. Попросите ссылку, которая начинается с https","no_servers":"В подписке нет серверов, которые приложение умеет использовать","unsupported_format":"Приложение не умеет читать такую подписку. Обновите приложение или попросите у провайдера другую ссылку","service_error":"Приложению не удалось это добавить. Повторите; если не помогает, перезапустите Mistgate"},
    onlyKinds: (k) => `В подписке только протоколы, которые приложение не поддерживает: ${k}`,
    neighbours: ["Другие VPN-программы","Найдены","Они могут мешать соединению: закройте их, пока включён Mistgate"],
    throttled: "Скорость через VPN падает после первых секунд",
    diagFail: { no_subscription: ["Пока нечего проверять", "Сначала добавьте подписку: проверка тестирует её серверы"], offline: ["Нет интернета", "Подключитесь к сети и запустите проверку снова"] },
    off: 'выключен',
    modes: ['Только выбранное', 'Всё', 'Умный'],
    notify: { lost: ['Связь потеряна', 'Нет ответа 30 секунд. Mistgate пробует снова.'], backup: ['Перешли на резервный путь', (way) => `Прежний путь перестал отвечать, поэтому Mistgate перевёл вас на ${way}.`], ends: [(days) => `Подписка заканчивается через ${days}`, (name, date) => `«${name}» заканчивается ${date}. Продлите её, чтобы VPN продолжал работать.`], removed: ['Этот ПК удалён', (name) => `Компьютера больше нет в подписке «${name}» — VPN не подключится.`] },
    dbg: { wait: (min) => `Отправить снова можно через ${min} мин`, offline: 'Нет связи с сервером администратора. Попробуйте позже', gone: 'Администратор больше не ждёт эту диагностику', full: 'У администратора закончилось место для диагностики. Сообщите ему напрямую', fail: 'Не удалось отправить. Попробуйте позже', look: 'Вот что будет отправлено. Проверьте и нажмите «Отправить» ещё раз' },
    proxyBusy: 'Не удалось запустить · порт 1080 или 8080 занят другой программой',
    synced: (t) => `Обновлено ${t}`,
    chk: ['VPN', 'Напрямую', 'Заблокирован', 'Правило: режим «Всё»', 'Правило: «%s» включено', 'Правило: нет в вашем выборе', 'Правило: «%s» идёт напрямую', 'Правило: не исключение'],
    lists: { region: (cc) => `Адреса ${cc}`, entries: (n) => `записей: ${n}`, updated: (t) => `обновлён ${t}`, failed: 'Не удалось обновить', checking: 'Проверяем ссылку…' },
  },
  tr: {
    locale: 'tr-TR', wl: ["Beyaz listeler için","yanıt veriyor","yanıt yok"], trayMenu: ["Mistgate’i aç", "Çıkış"], noCert: 'doğrulamasız', noCertFull: 'sertifika doğrulanmıyor', days: (n) => `${n} gün`, left: (d) => `${d} kaldı`, until: (d) => `bitiş: ${d}`,
    lifetime: 'Süresiz', noEnd: 'süresiz', noEndCap: 'Süresiz', expired: 'Süresi doldu', expiredOn: (d) => d,
    expiredMeta: (d) => `${d} tarihinde bitti`, servers: (n) => `${n} sunucu`, gb: 'GB',
    leftOf: (t) => `kalan / ${t}`, used: 'kullanıldı · sınırsız', renew: 'kullanmak için yenileyin', link: 'Bağlantı', file: 'Dosya',
    stale: (t, why = 'Güncellenemedi') => `${why} · ${t} kopyası kullanılıyor`, validUntil: 'bitiş tarihi', add: (s) => `${s} ekle`,
    dnsReplaced: "Bu ağda bazı site adresleri değiştiriliyor", dnsReplacedLine: (n, m) => `${m} test sitesinden ${n} tanesinin adresi değiştirilmiş`, foreignCut: "Bu ağda bazı yabancı siteler kesiliyor",
    subErr: {"device_removed":"Bu cihaz abonelikten kaldırıldı · bağlantıyı yeniden ekleyin","device_blocked":"Bu cihaz sağlayıcı tarafından engellendi","link_changed":"Bağlantı değiştirildi · yenisini yapıştırın","device_limit":"Cihaz sınırına ulaşıldı · abonelik sayfasında bir cihazı kaldırın","device_exists":"Bu cihaz zaten kayıtlı · abonelik sayfasında kaldırın","app_disabled":"Uygulama bu hesap için kapatıldı · sağlayıcınıza başvurun","disabled":"Abonelik sağlayıcı tarafından kapatıldı","expired":"Aboneliğin süresi doldu","limited":"Trafik tükendi","client_api_off":"Sağlayıcı bu abonelikte uygulamaya izin vermiyor · sağlayıcınıza başvurun","user_inactive":"Abonelik etkin değil · sağlayıcınıza başvurun","too_many_requests":"Çok fazla istek · birkaç dakika bekleyip tekrar deneyin"},
    keep: {"offline":"İnternet yok","fetch_failed":"Sağlayıcının sunucusu yanıt vermedi","unsupported_format":"Bu aboneliği okumak için uygulamayı güncelleyin"},
    addErr: {"offline":"İnternet bağlantısı yok. Bir ağa bağlanıp tekrar deneyin","service_down":"Mistgate hizmeti yanıt vermiyor. Biraz bekleyip tekrar deneyin","timeout":"Zamanında yanıt gelmedi. Bir dakika sonra tekrar deneyin","insecure_link":"Şifrelenmemiş (http) bağlantı kabul edilmez. https ile başlayan bir bağlantı isteyin","no_servers":"Bu abonelikte uygulamanın kullanabileceği sunucu yok","unsupported_format":"Uygulama bu tür aboneliği okuyamıyor. Uygulamayı güncelleyin ya da sağlayıcınızdan başka bir bağlantı isteyin","service_error":"Uygulama bunu ekleyemedi. Tekrar deneyin; sürerse Mistgate’i yeniden başlatın"},
    onlyKinds: (k) => `Abonelikte yalnızca uygulamanın desteklemediği protokoller var: ${k}`,
    neighbours: ["Diğer VPN programları","Bulundu","Bağlantıyı bozabilirler: Mistgate açıkken onları kapatın"],
    throttled: "VPN üzerinden hız ilk saniyelerden sonra düşüyor",
    diagFail: { no_subscription: ["Henüz kontrol edilecek bir şey yok", "Önce bir abonelik ekleyin: kontrol onun sunucularını test eder"], offline: ["İnternet yok", "Bir ağa bağlanın ve kontrolü yeniden başlatın"] },
    off: 'kapalı',
    modes: ['Yalnızca seçilenler', 'Her şey', 'Akıllı'],
    notify: { lost: ['Bağlantı koptu', '30 saniyedir yanıt yok. Mistgate denemeyi sürdürüyor.'], backup: ['Yedek yola geçildi', (way) => `Önceki yol yanıt vermeyi bıraktı; Mistgate sizi ${way} yoluna geçirdi.`], ends: [(_days, n) => `Abonelik ${n} gün sonra bitiyor`, (name, date) => `“${name}” ${date} tarihinde bitiyor. VPN’in çalışması için yenileyin.`], removed: ['Bu bilgisayar kaldırıldı', (name) => `Artık “${name}” içinde değil, bu yüzden VPN bağlanamıyor.`] },
    dbg: { wait: (min) => `${min} dk sonra yeniden gönderebilirsiniz`, offline: 'Yöneticinizin sunucusuna bağlanılamadı. Daha sonra deneyin', gone: 'Yöneticiniz artık bu tanılama verisini beklemiyor', full: 'Yöneticinizin tanılama deposu dolu. Ona doğrudan bildirin', fail: 'Gönderilemedi. Daha sonra deneyin', look: 'Gönderilecek olan bu. Kontrol edip yeniden Gönder’e basın' },
    proxyBusy: 'Başlatılamadı · 1080 veya 8080 portu başka bir program tarafından kullanılıyor',
    synced: (t) => `Güncellendi: ${t}`,
    chk: ['VPN', 'Doğrudan', 'Engelli', 'Kural: “Her şey” modu', 'Kural: “%s” açık', 'Kural: seçiminizde yok', 'Kural: “%s” doğrudan gider', 'Kural: istisna değil'],
    lists: { region: (cc) => `${cc} adresleri`, entries: (n) => `${n} kayıt`, updated: (t) => `güncellendi: ${t}`, failed: 'Güncellenemedi', checking: 'Bağlantı kontrol ediliyor…' },
  },
  zh: {
    locale: 'zh-CN', wl: ["白名单专用","有响应","无响应"], trayMenu: ["打开 Mistgate", "退出"], noCert: '未验证', noCertFull: '不验证证书', days: (n) => `${n} 天`, left: (d) => `剩余 ${d}`, until: (d) => `至 ${d}`,
    lifetime: '永久', noEnd: '无到期日', noEndCap: '无到期日', expired: '已到期', expiredOn: (d) => d,
    expiredMeta: (d) => `已于 ${d}到期`, servers: (n) => `${n} 个服务器`, gb: 'GB',
    leftOf: (t) => `剩余 / 共 ${t}`, used: '已用 · 无上限', renew: '续订后可用', link: '链接', file: '文件',
    stale: (t, why = '更新失败') => `${why} · 正在使用 ${t} 的副本`, validUntil: '有效期至', add: (s) => `添加 ${s}`,
    dnsReplaced: "此网络会替换部分网站的地址", dnsReplacedLine: (n, m) => `${m} 个测试网站中有 ${n} 个的地址被替换`, foreignCut: "此网络屏蔽了部分境外网站",
    subErr: {"device_removed":"此设备已从订阅中移除 · 请重新添加链接","device_blocked":"此设备已被服务商封禁","link_changed":"链接已更换 · 请粘贴新链接","device_limit":"设备数已达上限 · 请在订阅页面移除一台设备","device_exists":"此设备已注册 · 请在订阅页面将其移除","app_disabled":"此账户已停用本应用 · 请联系服务商","disabled":"订阅已被服务商停用","expired":"订阅已到期","limited":"流量已用完","client_api_off":"服务商不允许此订阅使用本应用 · 请联系服务商","user_inactive":"订阅未生效 · 请联系服务商","too_many_requests":"请求过于频繁 · 请等几分钟再试"},
    keep: {"offline":"无网络","fetch_failed":"服务商的服务器没有响应","unsupported_format":"请更新应用以读取此订阅"},
    addErr: {"offline":"没有网络连接。请连接网络后重试","service_down":"Mistgate 服务没有响应。请稍等后重试","timeout":"等待响应超时。请一分钟后重试","insecure_link":"不接受未加密（http）的链接。请索取以 https 开头的链接","no_servers":"此订阅中没有应用可用的服务器","unsupported_format":"应用无法读取这种订阅。请更新应用，或向服务商索取其他链接","service_error":"应用无法添加此订阅。请重试；若仍失败，请重启 Mistgate"},
    onlyKinds: (k) => `订阅中只有应用不支持的协议：${k}`,
    neighbours: ["其他 VPN 程序","已发现","它们可能干扰连接：使用 Mistgate 时请关闭它们"],
    throttled: "通过 VPN 的速度在最初几秒后下降",
    diagFail: { no_subscription: ["暂无可检查的内容", "请先添加订阅：检查会测试其中的服务器"], offline: ["无网络连接", "请连接网络后重新检查"] },
    off: '已关闭',
    modes: ['仅所选', '全部', '智能'],
    notify: { lost: ['连接已断开', '30 秒无响应。Mistgate 正在重试。'], backup: ['已切换到备用线路', (way) => `原线路不再响应，Mistgate 已将您切换到 ${way}。`], ends: [(_days, n) => `订阅将在 ${n} 天后到期`, (name, date) => `“${name}”将于 ${date} 到期。续订后 VPN 才能继续使用。`], removed: ['这台电脑已被移除', (name) => `这台电脑已不在“${name}”中，VPN 无法连接。`] },
    dbg: { wait: (min) => `${min} 分钟后可再次发送`, offline: '无法连接管理员的服务器，请稍后再试', gone: '管理员已不再等待这份诊断', full: '管理员的诊断存储已满，请直接告知对方', fail: '发送失败，请稍后再试', look: '以下是将要发送的内容，请检查后再次点击发送' },
    proxyBusy: '无法启动 · 端口 1080 或 8080 已被其他程序占用',
    synced: (t) => `更新于 ${t}`,
    chk: ['VPN', '直连', '已拦截', '规则：“全部”模式', '规则：“%s”已开启', '规则：不在您的选择中', '规则：“%s”直连', '规则：不在例外中'],
    lists: { region: (cc) => `${cc} 地址`, entries: (n) => `${n} 条`, updated: (t) => `更新于 ${t}`, failed: '更新失败', checking: '正在检查链接…' },
  },
  fa: {
    locale: 'fa-IR-u-ca-gregory-nu-latn', wl: ["برای لیست‌های سفید","پاسخ می‌دهد","پاسخ نمی‌دهد"], trayMenu: ["بازکردن Mistgate", "خروج"], noCert: 'بدون بررسی', noCertFull: 'بدون بررسی گواهی', days: (n) => `${n} روز`, left: (d) => `${d} مانده`, until: (d) => `تا ${d}`,
    lifetime: 'مادام‌العمر', noEnd: 'بدون تاریخ پایان', noEndCap: 'بدون تاریخ پایان', expired: 'منقضی‌شده', expiredOn: (d) => d,
    expiredMeta: (d) => `انقضا در ${d}`, servers: (n) => `${n} سرور`, gb: 'گیگابایت',
    leftOf: (t) => `مانده از ${t}`, used: 'مصرف‌شده · بدون سقف', renew: 'برای استفاده تمدید کنید', link: 'لینک', file: 'فایل',
    stale: (t, why = 'به‌روزرسانی نشد') => `${why} · نسخهٔ ${t} استفاده می‌شود`, validUntil: 'معتبر تا', add: (s) => `افزودن ${s}`,
    dnsReplaced: "در این شبکه نشانی برخی سایت‌ها جایگزین می‌شود", dnsReplacedLine: (n, m) => `نشانی ${n} سایت از ${m} سایت آزمایشی جایگزین شده است`, foreignCut: "برخی سایت‌های خارجی در این شبکه قطع هستند",
    subErr: {"device_removed":"این دستگاه از اشتراک حذف شده است · لینک را دوباره اضافه کنید","device_blocked":"این دستگاه توسط ارائه‌دهنده مسدود شده است","link_changed":"لینک عوض شده است · لینک جدید را وارد کنید","device_limit":"به سقف دستگاه‌ها رسیده‌اید · یک دستگاه را در صفحهٔ اشتراک حذف کنید","device_exists":"این دستگاه قبلاً ثبت شده است · آن را در صفحهٔ اشتراک حذف کنید","app_disabled":"برنامه برای این حساب خاموش شده است · با ارائه‌دهنده تماس بگیرید","disabled":"اشتراک توسط ارائه‌دهنده غیرفعال شده است","expired":"مهلت اشتراک تمام شده است","limited":"ترافیک تمام شده است","client_api_off":"ارائه‌دهنده استفاده از برنامه را برای این اشتراک مجاز نکرده است · با ارائه‌دهنده تماس بگیرید","user_inactive":"اشتراک فعال نیست · با ارائه‌دهنده تماس بگیرید","too_many_requests":"درخواست‌ها بیش از حد است · چند دقیقه صبر کنید و دوباره امتحان کنید"},
    keep: {"offline":"اینترنت قطع است","fetch_failed":"سرور ارائه‌دهنده پاسخ نداد","unsupported_format":"برای خواندن این اشتراک برنامه را به‌روز کنید"},
    addErr: {"offline":"اتصال اینترنت وجود ندارد. به شبکه وصل شوید و دوباره امتحان کنید","service_down":"سرویس Mistgate پاسخ نمی‌دهد. کمی صبر کنید و دوباره امتحان کنید","timeout":"پاسخ به‌موقع نرسید. یک دقیقه بعد دوباره امتحان کنید","insecure_link":"لینک بدون رمزگذاری (http) پذیرفته نمی‌شود. لینکی بخواهید که با https شروع شود","no_servers":"در این اشتراک سروری که برنامه بتواند استفاده کند نیست","unsupported_format":"برنامه این نوع اشتراک را نمی‌خواند. برنامه را به‌روز کنید یا از ارائه‌دهنده لینک دیگری بخواهید","service_error":"برنامه نتوانست این را اضافه کند. دوباره امتحان کنید؛ اگر تکرار شد، Mistgate را دوباره راه‌اندازی کنید"},
    onlyKinds: (k) => `در اشتراک فقط پروتکل‌هایی است که برنامه پشتیبانی نمی‌کند: ${k}`,
    neighbours: ["برنامه‌های VPN دیگر","پیدا شد","ممکن است اتصال را مختل کنند: هنگام روشن بودن Mistgate آن‌ها را ببندید"],
    throttled: "سرعت از طریق VPN پس از چند ثانیهٔ اول افت می‌کند",
    diagFail: { no_subscription: ["هنوز چیزی برای بررسی نیست", "ابتدا یک اشتراک اضافه کنید: بررسی، سرورهای آن را می‌آزماید"], offline: ["اینترنت در دسترس نیست", "به یک شبکه وصل شوید و بررسی را دوباره اجرا کنید"] },
    off: 'خاموش',
    modes: ['فقط انتخابی‌ها', 'همه‌چیز', 'هوشمند'],
    notify: { lost: ['اتصال قطع شد', '30 ثانیه پاسخی نیامد. Mistgate دوباره تلاش می‌کند.'], backup: ['به مسیر پشتیبان جابه‌جا شد', (way) => `مسیر قبلی دیگر پاسخ نمی‌داد؛ Mistgate شما را به ${way} منتقل کرد.`], ends: [(_days, n) => `اشتراک ${n} روز دیگر تمام می‌شود`, (name, date) => `«${name}» ${date} تمام می‌شود. برای ادامه کار VPN آن را تمدید کنید.`], removed: ['این رایانه حذف شده', (name) => `این رایانه دیگر در «${name}» نیست و VPN وصل نمی‌شود.`] },
    dbg: { wait: (min) => `${min} دقیقهٔ دیگر می‌توانید دوباره بفرستید`, offline: 'اتصال به سرور مدیر برقرار نشد. بعداً دوباره تلاش کنید', gone: 'مدیر دیگر منتظر این عیب‌یابی نیست', full: 'فضای عیب‌یابی مدیر پر شده است. مستقیم به او بگویید', fail: 'ارسال نشد. بعداً دوباره تلاش کنید', look: 'این چیزی است که فرستاده می‌شود. بررسی کنید و دوباره ارسال را بزنید' },
    proxyBusy: 'راه‌اندازی نشد · درگاه 1080 یا 8080 را برنامهٔ دیگری گرفته است',
    synced: (t) => `به‌روزرسانی ${t}`,
    chk: ['VPN', 'مستقیم', 'مسدود', 'قاعده: حالت «همه‌چیز»', 'قاعده: «%s» روشن است', 'قاعده: در انتخاب شما نیست', 'قاعده: «%s» مستقیم می‌رود', 'قاعده: استثنا نیست'],
    lists: { region: (cc) => `نشانی‌های ${cc}`, entries: (n) => `${n} مورد`, updated: (t) => `به‌روزرسانی ${t}`, failed: 'به‌روزرسانی نشد', checking: 'در حال بررسی لینک…' },
  },
};

// built once per language: the formatters are costly and a screen asks for the words many times a render (the
// language only changes with a reload of the page)
let built: { lang: string; value: ReturnType<typeof build> } | null = null;
export function words() {
  const lang = document.documentElement.lang;
  if (built?.lang !== lang) built = { lang, value: build() };
  return built.value;
}
function build() {
  const w = WORDS[document.documentElement.lang] ?? WORDS.en;
  const number = new Intl.NumberFormat(w.locale, { maximumFractionDigits: 1 });
  const day = new Intl.DateTimeFormat(w.locale, { day: 'numeric', month: w === WORDS.en ? 'short' : 'long' });
  const clock = new Intl.DateTimeFormat(w.locale, { hour: '2-digit', minute: '2-digit', hourCycle: 'h23' });
  return {
    ...w,
    // looked up by the service's code, which is any string
    keep: w.keep as Record<string, string>,
    addErr: w.addErr as Record<string, string>,
    date: (unix: number) => day.format(unix * 1000),
    time: (unix: number) => clock.format(unix * 1000),
    size: (bytes: number) => `${number.format(bytes / 2 ** 30)} ${w.gb}`,
  };
}
