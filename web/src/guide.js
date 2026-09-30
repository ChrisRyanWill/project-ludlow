// The "Next step" card: one quiet suggestion from shared/guide.js, with a button that takes the person to the right place on the page (scrolled into
// view and briefly outlined) or to another page. It can be hidden per step and never blocks anything. Nothing is shown when there is nothing to do.
import { t } from './i18n.js';
import { div, p, strong, span, btn, linkBtn } from './ui.js';
import { store } from './store.js';

const hiddenKey = (scope, id) => `guide.hidden.${scope}.${id}`;

export function nextStepCard(step, scope) {
  if (!step || store.get(hiddenKey(scope, step.id))) return null;
  const v = step.vars || {};
  const show = () => {
    const el = document.getElementById(step.target);
    if (!el) return;
    el.scrollIntoView({ behavior: 'smooth', block: 'start' });
    el.classList.add('guide-glow');
    setTimeout(() => el.classList.remove('guide-glow'), 2200);
    const first = el.querySelector('button:not([disabled]), input, a[href], summary');
    if (first) setTimeout(() => first.focus({ preventScroll: true }), 400);
  };
  const card = div({ class: 'next-step', role: 'status' },
    div(span({ class: 'next-step-label' }, t('Next step')), ' ', strong(t(step.title, v))),
    p({ class: 'small muted' }, t(step.why, v)),
    div({ class: 'row' },
      step.href ? linkBtn(t('Go there'), step.href, 'primary small') : btn(t('Show me'), show, { kind: 'primary small' }),
      btn(t('Hide this'), () => { store.set(hiddenKey(scope, step.id), true); card.remove(); }, { kind: 'secondary small' })));
  return card;
}
