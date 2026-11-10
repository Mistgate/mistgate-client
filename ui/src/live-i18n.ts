// The words Home needs around real numbers and dates. The wording is the design's (its sample subscriptions in each
// language); here it is turned into patterns. ponytail: tr, zh and fa follow the design's samples but were not read
// by a native speaker.
type Words = {
  locale: string;
  days: (n: number) => string;
  left: (days: string) => string;
  until: (date: string) => string;
  lifetime: string;
  noEnd: string;
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
  stale: (time: string) => string;
  validUntil: string;
  add: (servers: string) => string;
  dnsReplaced: string;
  dnsReplacedLine: (replaced: number, checked: number) => string;
  foreignCut: string;
};

const ruForm = (n: number, one: string, few: string, many: string) =>
  ({ one, few, many, other: many } as Record<string, string>)[new Intl.PluralRules('ru').select(n)];
const enForm = (n: number, one: string, other: string) => (n === 1 ? one : other);

const WORDS: Record<string, Words> = {
  en: {
    locale: 'en-US', days: (n) => `${n} ${enForm(n, 'day', 'days')}`, left: (d) => `${d} left`, until: (d) => `until ${d}`,
    lifetime: 'Lifetime', noEnd: 'no end date', noEndCap: 'No end date', expired: 'Expired', expiredOn: (d) => `on ${d}`,
    expiredMeta: (d) => `expired ${d}`, servers: (n) => `${n} ${enForm(n, 'server', 'servers')}`, gb: 'GB',
    leftOf: (t) => `left of ${t}`, used: 'used · no cap', renew: 'renew to use', link: 'Link', file: 'File',
    stale: (t) => `Couldn’t update · using the copy from ${t}`, validUntil: 'valid until', add: (s) => `Add ${s}`,
    dnsReplaced: "Some site addresses are replaced on this network", dnsReplacedLine: (n, m) => `${n} of ${m} test sites got a replaced address`, foreignCut: "Some foreign sites are cut off on this network",
  },
  ru: {
    locale: 'ru-RU', days: (n) => `${n} ${ruForm(n, 'день', 'дня', 'дней')}`, left: (d) => `осталось ${d}`, until: (d) => `до ${d}`,
    lifetime: 'Бессрочно', noEnd: 'бессрочно', noEndCap: 'Бессрочно', expired: 'Истекла', expiredOn: (d) => d,
    expiredMeta: (d) => `истекла ${d}`, servers: (n) => `${n} ${ruForm(n, 'сервер', 'сервера', 'серверов')}`, gb: 'ГБ',
    leftOf: (t) => `осталось из ${t}`, used: 'израсходовано · без лимита', renew: 'продлите, чтобы пользоваться', link: 'Ссылка', file: 'Файл',
    stale: (t) => `Не удалось обновить · используется копия от ${t}`, validUntil: 'действует до', add: (s) => `Добавить ${s}`,
    dnsReplaced: "В этой сети подменяют адреса некоторых сайтов", dnsReplacedLine: (n, m) => `Подменён адрес у ${n} из ${m} проверенных сайтов`, foreignCut: "Часть зарубежных сайтов в этой сети недоступна",
  },
  tr: {
    locale: 'tr-TR', days: (n) => `${n} gün`, left: (d) => `${d} kaldı`, until: (d) => `bitiş: ${d}`,
    lifetime: 'Süresiz', noEnd: 'süresiz', noEndCap: 'Süresiz', expired: 'Süresi doldu', expiredOn: (d) => d,
    expiredMeta: (d) => `${d} tarihinde bitti`, servers: (n) => `${n} sunucu`, gb: 'GB',
    leftOf: (t) => `kalan / ${t}`, used: 'kullanıldı · sınırsız', renew: 'kullanmak için yenileyin', link: 'Bağlantı', file: 'Dosya',
    stale: (t) => `Güncellenemedi · ${t} kopyası kullanılıyor`, validUntil: 'bitiş tarihi', add: (s) => `${s} ekle`,
    dnsReplaced: "Bu ağda bazı site adresleri değiştiriliyor", dnsReplacedLine: (n, m) => `${m} test sitesinden ${n} tanesinin adresi değiştirilmiş`, foreignCut: "Bu ağda bazı yabancı siteler kesiliyor",
  },
  zh: {
    locale: 'zh-CN', days: (n) => `${n} 天`, left: (d) => `剩余 ${d}`, until: (d) => `至 ${d}`,
    lifetime: '永久', noEnd: '无到期日', noEndCap: '无到期日', expired: '已到期', expiredOn: (d) => d,
    expiredMeta: (d) => `已于 ${d}到期`, servers: (n) => `${n} 个服务器`, gb: 'GB',
    leftOf: (t) => `剩余 / 共 ${t}`, used: '已用 · 无上限', renew: '续订后可用', link: '链接', file: '文件',
    stale: (t) => `更新失败 · 正在使用 ${t} 的副本`, validUntil: '有效期至', add: (s) => `添加 ${s}`,
    dnsReplaced: "此网络会替换部分网站的地址", dnsReplacedLine: (n, m) => `${m} 个测试网站中有 ${n} 个的地址被替换`, foreignCut: "此网络屏蔽了部分境外网站",
  },
  fa: {
    locale: 'fa-IR-u-ca-gregory-nu-latn', days: (n) => `${n} روز`, left: (d) => `${d} مانده`, until: (d) => `تا ${d}`,
    lifetime: 'مادام‌العمر', noEnd: 'بدون تاریخ پایان', noEndCap: 'بدون تاریخ پایان', expired: 'منقضی‌شده', expiredOn: (d) => d,
    expiredMeta: (d) => `انقضا در ${d}`, servers: (n) => `${n} سرور`, gb: 'گیگابایت',
    leftOf: (t) => `مانده از ${t}`, used: 'مصرف‌شده · بدون سقف', renew: 'برای استفاده تمدید کنید', link: 'لینک', file: 'فایل',
    stale: (t) => `به‌روزرسانی نشد · نسخهٔ ${t} استفاده می‌شود`, validUntil: 'معتبر تا', add: (s) => `افزودن ${s}`,
    dnsReplaced: "در این شبکه نشانی برخی سایت‌ها جایگزین می‌شود", dnsReplacedLine: (n, m) => `نشانی ${n} سایت از ${m} سایت آزمایشی جایگزین شده است`, foreignCut: "برخی سایت‌های خارجی در این شبکه قطع هستند",
  },
};

export function words() {
  const w = WORDS[document.documentElement.lang] ?? WORDS.en;
  const number = new Intl.NumberFormat(w.locale, { maximumFractionDigits: 1 });
  const day = new Intl.DateTimeFormat(w.locale, { day: 'numeric', month: w === WORDS.en ? 'short' : 'long' });
  const clock = new Intl.DateTimeFormat(w.locale, { hour: '2-digit', minute: '2-digit' });
  return {
    ...w,
    date: (unix: number) => day.format(unix * 1000),
    time: (unix: number) => clock.format(unix * 1000),
    size: (bytes: number) => `${number.format(bytes / 2 ** 30)} ${w.gb}`,
  };
}
