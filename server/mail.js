// Email adapters. The Confirmation Transmission is the ONE place the server briefly handles a signer's
// plaintext (rule 2): it is composed, sent, and discarded. Only the provider's message id is kept.
import { randomUUID } from 'node:crypto';

export function makeMailer(cfg) {
  if (cfg.emailProvider === 'postmark') {
    return {
      async send({ to, subject, text, replyTo }) {
        const r = await fetch('https://api.postmarkapp.com/email', {
          method: 'POST',
          headers: { 'X-Postmark-Server-Token': cfg.postmarkToken, 'Content-Type': 'application/json', Accept: 'application/json' },
          // Open and click tracking OFF (rule 15): click tracking would rewrite links through the provider.
          body: JSON.stringify({ From: cfg.emailFrom, To: to, Subject: subject, TextBody: text, ReplyTo: replyTo || undefined, TrackOpens: false, TrackLinks: 'None', MessageStream: 'outbound' }),
        });
        if (!r.ok) throw new Error('email_provider_error');
        return { messageId: (await r.json()).MessageID };
      },
    };
  }
  // Dev adapter: an in-memory outbox that dies with the process. Never written to disk or logs.
  const outbox = [];
  return {
    outbox,
    async send(m) {
      outbox.push({ ...m, at: new Date().toISOString() });
      if (outbox.length > 50) outbox.shift();
      return { messageId: 'dev-' + randomUUID() };
    },
  };
}

// The Confirmation Transmission required for simple e-signatures (NLRB GC Memo 15-08): restates the
// signer's name, contact info, the exact card language, the date signed and the employer.
export function confirmationEmail({ appName, baseUrl, card, signedAt, cardId, disavowToken, templateVersion }) {
  const link = `${baseUrl}/d#t=${disavowToken}&c=${cardId}`;
  return {
    subject: 'Confirmation: you signed a union authorization card',
    text: [
      'This message confirms that a union authorization card was signed electronically using your name.',
      '',
      `Name: ${card.legalName}`,
      `Email: ${card.to}`,
      `Phone: ${card.phone}`,
      `Employer: ${card.employerName}`,
      `Union: ${card.unionName}`,
      `Date and time signed: ${signedAt} (UTC)`,
      `Card version: ${templateVersion}`,
      '',
      'The card said:',
      `"${card.cardText}"`,
      '',
      'If YOU signed this card, no action is needed. Keep this message for your records.',
      '',
      'If you did NOT sign this card, open this link to say so:',
      link,
      '',
      'If anything above is wrong, reply to this email. Replies go to the organizing committee.',
      '',
      `Sent by ${appName} on behalf of the organizing committee. ${appName} is a tool. It is not a union and not a law firm.`,
    ].join('\n'),
  };
}
