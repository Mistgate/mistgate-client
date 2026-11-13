// "Help find blocks": the person's switch for anonymous block reports to the panel of a subscription. What the two
// screens that show it (Settings > Privacy and Diagnostics) share: the state of a subscription, and the words the
// design does not have.

export type ReportSub = {
  id: string; name: string; managed?: boolean;
  probe?: { intake: boolean; v: number }; // the panel's side: whether its owner takes reports from apps
  report?: boolean; // the person's switch
  report_last?: { at_unix: number; accepted: number; error: string };
};

// can: the panel takes reports; on: the person switched them on; at: when the last one was accepted today, or null
export function reportState(u: ReportSub | null | undefined) {
  const can = !!u?.managed && !!u.probe?.intake && (u.probe.v ?? 0) >= 1;
  const last = u?.report_last && !u.report_last.error && u.report_last.at_unix ? new Date(u.report_last.at_unix * 1000) : null;
  const today = !!last && last.toDateString() === new Date().toDateString();
  return { can, on: can && !!u?.report, at: today ? last : null, link: !!u && !u.managed };
}

export const clock = (d: Date) => String(d.getHours()).padStart(2, '0') + ':' + String(d.getMinutes()).padStart(2, '0');

// The design's sentences name its sample subscription; here they name the real one.
const SAMPLE: Record<string, string> = { en: 'My subscription', ru: 'Моя подписка', zh: '我的订阅', fa: 'اشتراک من', tr: 'Aboneliğim' };
export function named(text: string, name: string) {
  const lang = document.documentElement.lang || 'en';
  return String(text ?? '').replace('«Моей подписке»', `подписке «${name}»`).replace(SAMPLE[lang] ?? SAMPLE.en, name);
}

// A Mistgate panel whose owner has not switched app reports on. The design has words only for a panel too old for them.
const OFF: Record<string, string> = {
  en: 'The owner of this server hasn’t turned app reports on',
  ru: 'Владелец сервера не включил приём отчётов от приложения',
  zh: '服务器的管理者尚未开启应用报告',
  fa: 'مدیر این سرور دریافت گزارش از برنامه را روشن نکرده است',
  tr: 'Bu sunucunun sahibi uygulama raporlarını açmadı',
};
export const reportOff = () => OFF[document.documentElement.lang] ?? OFF.en;
