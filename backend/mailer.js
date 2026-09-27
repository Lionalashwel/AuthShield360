/**
 * AuthShield 360 - Mail transport (Nodemailer + Ethereal)
 * Creates an Ethereal test account lazily. Every e-mail (verification link,
 * fallback OTP, step-up codes) is sent through real SMTP and its preview URL
 * is exposed so testers can open the "sent" message in a browser.
 *
 * If Ethereal's API is unreachable (offline lab), we degrade to a console
 * transport that prints the message body - the app remains fully testable.
 */
import nodemailer from 'nodemailer';

let transport = null;
let current = null;   // current Ethereal account {user, pass, web}
let degraded = false;

const CONNECT_TIMEOUT_MS = 8000;

export async function ensureMailer() {
    if (transport) return transport;
    try {
        const account = await Promise.race([
            nodemailer.createTestAccount(),
            new Promise((_, rej) => setTimeout(() => rej(new Error('ethereal-timeout')), CONNECT_TIMEOUT_MS)),
        ]);
        current = account;
        transport = nodemailer.createTransport({
            host: 'smtp.ethereal.email',
            port: 587,
            secure: false,
            auth: { user: account.user, pass: account.pass },
        });
    } catch (err) {
        degraded = true;
        transport = { async sendMail() { throw new Error('ethereal-unavailable'); } };
    }
    return transport;
}

export function isDegraded() { return degraded; }
export function etherealInfo() {
    if (!current) return null;
    return { user: current.user, pass: current.pass, previewBase: current.web || 'https://ethereal.email' };
}

/** Send a mail; resolves { status, messageId, previewUrl } */
export async function sendMail({ to, subject, html, text }) {
    await ensureMailer();
    if (degraded) {
        // offline fallback: print the payload to stdout for the lab operator
        const previewUrl = `#degraded(no ethereal)`;
        console.log('\n[mail-degraded] to=%s subject=%s\n%s\n'.replace(/\\n/g, '\n')
            .replace('%s', String(to)).replace('%s', String(subject)).replace('%s', String(text || '')),
        );
        return { status: 'degraded', messageId: null, previewUrl, to };
    }
    const info = await transport.sendMail({
        from: `"AuthShield 360" <${current.user}>`,
        to, subject,
        html: html || `<pre>${String(text || '')}</pre>`,
        text: text || '',
    });
    const previewUrl = nodemailer.getTestMessageUrl(info);
    return { status: 'sent', messageId: info.messageId, previewUrl, to, account: etherealInfo() };
}