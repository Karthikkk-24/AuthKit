import { redactSecrets } from './config-loader.service';

describe('redactSecrets (#62)', () => {
  it('redacts password, apiKey, clientSecret leaves', () => {
    const input = {
      email: {
        smtp: { host: 'smtp.example.com', password: 's3cret', user: 'mailer' },
        sendgrid: { apiKey: 'SG.live' },
      },
      auth: {
        strategies: {
          google: { enabled: true, clientId: 'cid', clientSecret: 'csec' },
        },
      },
      ui: { theme: 'dark' },
    };

    const out = redactSecrets(input);

    expect(out.email.smtp.password).toBe('[REDACTED]');
    expect(out.email.smtp.host).toBe('smtp.example.com');
    expect(out.email.smtp.user).toBe('mailer');
    expect(out.email.sendgrid.apiKey).toBe('[REDACTED]');
    expect(out.auth.strategies.google.clientSecret).toBe('[REDACTED]');
    expect(out.auth.strategies.google.clientId).toBe('cid');
    expect(out.ui.theme).toBe('dark');
  });

  it('does not mutate the original object', () => {
    const input = { smtp: { password: 'live' } };
    redactSecrets(input);
    expect(input.smtp.password).toBe('live');
  });
});
