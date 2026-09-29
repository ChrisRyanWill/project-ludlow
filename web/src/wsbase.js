// Workspace session and shared frame. The signed-in state lives only in memory: reload or quick-exit and
// it is gone, and getting back in needs the key file's passphrase again.
import * as C from '../../shared/crypto.js';
import { api } from './api.js';
import { t } from './i18n.js';
import { packOf } from './packs.js';
import { div, span, p, h1, a, nav, btn, badge, shell, wipers, go, linkBtn } from './ui.js';

export let WS = null; // { token, keys, memberId, workspaceId, info }
wipers.push(() => { WS = null; });
export const setWS = (v) => { WS = v; };

export async function signIn(keys, memberId) {
  const ch = await api('POST', '/api/auth/challenge');
  const signature = C.signAuth(keys.signSecretKey, { nonce: ch.nonce, route: 'POST /api/ws/auth/login', scope: memberId });
  return (await api('POST', '/api/ws/auth/login', { body: { memberId, challengeId: ch.challengeId, signature } })).token;
}

// Calls the API as the signed-in member, signing in again by itself if the session expired.
export async function wcall(method, path, body) {
  try { return await api(method, path, { body, auth: 'Bearer ' + WS.token }); } catch (e) {
    if (e.status === 401 && WS?.keys) { WS.token = await signIn(WS.keys, WS.memberId); return api(method, path, { body, auth: 'Bearer ' + WS.token }); }
    throw e;
  }
}
export async function refreshMe() { WS.info = await wcall('GET', '/api/ws/me'); return WS.info; }
export const can = (action) => !!WS?.info?.permissions.includes(action);
export const has = (role) => !!WS?.info?.roles.includes(role);
export const wsInfo = () => WS.info.workspace;
export const currency = () => packOf(wsInfo().jurisdiction).currency;
export const pack = () => packOf(wsInfo().jurisdiction);

export const needSignIn = () => shell(div({ class: 'wrap' }, h1(t('Sign in to your workspace')), p(t('Your workspace is protected by your key file and passphrase.')), linkBtn(t('Sign in'), '/w', 'primary')));
export const guarded = (fn) => async (params) => (WS ? fn(params) : needSignIn());

const TABS = [
  ['home', '/w', 'Home', () => true], ['votes', '/w/votes', 'Votes', () => can('vote.read')], ['help', '/w/help', 'Get help', () => true],
  ['money', '/w/money', 'Money', () => can('finance.read')], ['union', '/w/union', 'Union', () => true],
];
export function wsFrame(active, ...content) {
  const tabs = nav({ class: 'tabs', 'aria-label': t('Workspace') }, div({ class: 'tabs-in' }, TABS.filter((x) => x[3]()).map(([k, href, label]) => a({ href, 'aria-current': k === active ? 'page' : undefined }, t(label)))));
  return shell(div(
    div({ class: 'ws-head' }, div(span({ class: 'ws-union' }, WS.info.workspace.unionName), ' ', badge(WS.info.workspace.stage === 'recognized' ? t('Recognized') : t('Public, not yet recognized'), WS.info.workspace.stage === 'recognized' ? 'ok' : 'warn')),
      div({ class: 'row' }, span({ class: 'small muted' }, WS.info.member.name), btn(t('Lock'), () => { WS = null; go('/w'); }, { kind: 'secondary small' }))),
    ...content), { wide: true, nav: tabs });
}

export const urgencyBadge = (u) => {
  if (!u) return null;
  if (u.level === 'overdue') return badge(t('Overdue by {n} days', { n: -u.left }), 'bad');
  if (u.level === 'today') return badge(t('Due today'), 'bad');
  return badge(t('Due in {n} days', { n: u.left }), u.level === 'ok' ? '' : 'warn');
};
