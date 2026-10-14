'use strict';
// Run with: node tests/analyzer.test.js
const assert = require('node:assert/strict');
const T = require('../analyzer.js');

const ORDER = ['low', 'medium', 'high', 'critical'];
let failures = 0;
let passed = 0;

function check(name, fn) {
  try {
    fn();
    passed++;
    console.log('ok   ' + name);
  } catch (e) {
    failures++;
    console.log('FAIL ' + name + '\n     ' + e.message.split('\n').join('\n     '));
  }
}

function atLeast(input, min) {
  const r = T.analyze(input);
  assert.ok(!r.error, 'unexpected error ' + r.error);
  assert.ok(ORDER.indexOf(r.level) >= ORDER.indexOf(min),
    `expected at least ${min} but got ${r.level} (${r.score}) for: ${input}\n` +
    r.reasons.map(x => '  - ' + x.title).join('\n'));
}

function atMost(input, max) {
  const r = T.analyze(input);
  assert.ok(!r.error, 'unexpected error ' + r.error);
  assert.ok(ORDER.indexOf(r.level) <= ORDER.indexOf(max),
    `expected at most ${max} but got ${r.level} (${r.score}) for: ${input}\n` +
    r.reasons.map(x => '  - ' + x.title).join('\n'));
}

function hasReason(input, id) {
  const r = T.analyze(input);
  const all = r.reasons.concat(...r.links.map(l => l.reasons));
  assert.ok(all.some(x => x.id === id), `expected reason "${id}" for: ${input}\ngot: ` + all.map(x => x.id).join(', '));
}

function lacksReason(input, id) {
  const r = T.analyze(input);
  const all = r.reasons.concat(...r.links.map(l => l.reasons));
  assert.ok(!all.some(x => x.id === id), `did not expect reason "${id}" for: ${input}`);
}

/* ---- helpers ---- */
check('levenshtein basics', () => {
  assert.equal(T.levenshtein('kitten', 'sitting'), 3);
  assert.equal(T.levenshtein('amazon', 'amazom'), 1);
  assert.equal(T.levenshtein('', 'abc'), 3);
});

check('registrable domain', () => {
  assert.equal(T.registrableDomain('www.example.com'), 'example.com');
  assert.equal(T.registrableDomain('a.b.example.co.uk'), 'example.co.uk');
  assert.equal(T.registrableDomain('paypal.com.verify-account.xyz'), 'verify-account.xyz');
});

check('level thresholds', () => {
  assert.equal(T.levelFor(0), 'low');
  assert.equal(T.levelFor(24), 'low');
  assert.equal(T.levelFor(25), 'medium');
  assert.equal(T.levelFor(49), 'medium');
  assert.equal(T.levelFor(50), 'high');
  assert.equal(T.levelFor(74), 'high');
  assert.equal(T.levelFor(75), 'critical');
  assert.equal(T.levelFor(100), 'critical');
});

check('type detection', () => {
  assert.equal(T.detectType('https://example.com/a'), 'url');
  assert.equal(T.detectType('example.com/login'), 'url');
  assert.equal(T.detectType('192.168.0.1/login'), 'url');
  assert.equal(T.detectType('javascript:alert(1)'), 'url');
  assert.equal(T.detectType('Hello there, see example.com'), 'message');
  assert.equal(T.detectType('hello'), 'message');
});

check('empty and invalid input', () => {
  assert.equal(T.analyze('').error, 'empty');
  assert.equal(T.analyze('   \n ').error, 'empty');
  assert.equal(T.analyze('http://').error, 'invalid-url');
});

/* ---- URLs that should be clean ---- */
['https://www.paypal.com/signin', 'https://github.com/anthropics', 'https://en.wikipedia.org/wiki/Phishing',
  'https://www.amazon.in/gp/help', 'https://accounts.google.com/signin', 'example.com',
  'https://pineapple.com/recipes', 'https://www.bbc.co.uk/news'].forEach(u =>
  check('clean url stays low: ' + u, () => atMost(u, 'low')));

/* ---- URLs that should be flagged ---- */
check('http only is a minor flag', () => { hasReason('http://example.com', 'http'); atMost('http://example.com', 'low'); });
check('bare domain does not get an http flag', () => lacksReason('example.com', 'http'));
check('ip address url', () => { hasReason('http://192.168.1.10/login', 'ip'); atLeast('http://192.168.1.10/login', 'medium'); });
check('disguised ip address', () => hasReason('http://0x7f.1/login', 'ip-hidden'));
check('at-sign trick', () => { hasReason('https://paypal.com@evil-site.xyz/login', 'userinfo'); atLeast('https://paypal.com@evil-site.xyz/login', 'medium'); });
check('punycode host', () => hasReason('https://xn--pypal-4ve.com/login', 'punycode'));
check('shortener', () => hasReason('https://bit.ly/3abcd', 'shortener'));
check('subdomain brand trick', () => { hasReason('https://paypal.com.verify-account.xyz/', 'brand'); atLeast('https://paypal.com.verify-account.xyz/', 'high'); });
check('digit swap lookalike', () => { hasReason('https://paypa1.com/login', 'brand'); atLeast('https://paypa1.com/login', 'medium'); });
check('rn for m lookalike', () => hasReason('https://arnazon.com/deal', 'brand'));
check('zero for o lookalike', () => hasReason('https://micros0ft.com/', 'brand'));
check('one letter typo', () => hasReason('https://amazom.com/', 'brand'));
check('brand plus keyword', () => atLeast('http://paypa1-secure-login.xyz/verify?session=48213', 'high'));
check('brand name on unknown tld', () => hasReason('https://netflix.top/billing', 'brand'));
check('risky tld alone', () => hasReason('https://random-shop.xyz', 'tld'));
check('many subdomains', () => hasReason('https://a.b.c.d.example.com', 'subdomains'));
check('unusual port', () => hasReason('https://example.com:8443/login', 'port'));
check('redirect param', () => hasReason('https://example.com/go?next=https://evil.xyz', 'redirect-param'));
check('executable download', () => hasReason('https://example.com/invoice.exe', 'download'));
check('javascript scheme is high risk', () => { const r = T.analyze('javascript:alert(1)'); assert.equal(r.level, 'high'); assert.ok(r.reasons[0].id === 'scheme'); });
check('data scheme flagged', () => hasReason('data:text/html;base64,PHNjcmlwdD4=', 'scheme'));
check('score never exceeds 100', () => {
  const r = T.analyze('http://paypal.com.secure-login-verify-account.xyz:8080/login/verify/update.exe?u=https://x.xyz');
  assert.ok(r.score <= 100 && r.score >= 75, 'score ' + r.score);
});

/* ---- Messages ---- */
const PHISH = 'URGENT: Your bank account has been suspended due to unusual activity. Verify your identity within 24 hours or your account will be closed. Click here: http://secure-hdfc-update.top/login and enter your OTP and card number. Do not tell anyone.';
check('obvious phishing message is high or critical', () => atLeast(PHISH, 'high'));
check('phishing message lists several reasons', () => {
  const r = T.analyze(PHISH);
  const ids = r.reasons.map(x => x.id);
  ['urgency', 'threat', 'credentials', 'click', 'secrecy', 'combo'].forEach(id => assert.ok(ids.includes(id), 'missing ' + id));
});
check('prize scam', () => atLeast('Congratulations, you have won a cash prize! Claim your prize now by paying a small fee in gift cards. Dear customer, act now!!!', 'high'));
check('courier fee scam', () => atLeast('Your parcel is on hold. Pay the delivery fee at https://post-track.top/pay within 24 hours', 'high'));
check('brand mismatch in message', () => hasReason('Your PayPal account needs attention: https://account-check.example.xyz/login', 'brand-mismatch'));
check('legit security advice is not flagged for credentials', () => {
  lacksReason('Never share your OTP with anyone. Our staff will not ask for your password.', 'credentials');
  atMost('Never share your OTP with anyone. Our staff will not ask for your password.', 'low');
});
check('harmless message is low', () => atMost('Hi, the meeting notes are at https://docs.example.org/notes. See you at 3.', 'low'));
check('plain chat is low', () => atMost('Are we still on for lunch tomorrow? I can do 1pm.', 'low'));
check('email address is not treated as a link', () => {
  assert.deepEqual(T.extractUrls('write to support@paypal.com please'), []);
});
check('bare domains and trailing punctuation extracted', () => {
  assert.deepEqual(T.extractUrls('Visit paypa1-secure.com/verify, or http://a.example.com/x).'),
    ['http://a.example.com/x', 'paypa1-secure.com/verify']);
});
check('file names are not links', () => assert.deepEqual(T.extractUrls('see report.pdf and notes.txt'), []));
check('links in message are analyzed separately', () => {
  const r = T.analyze('Look at bit.ly/abc and http://192.168.0.1/x');
  assert.equal(r.links.length, 2);
});
check('at most ten links analyzed', () => {
  const many = Array.from({ length: 25 }, (_, i) => 'https://site' + i + '.example.com').join(' ');
  assert.equal(T.analyze(many).links.length, 10);
});
check('very long input does not crash', () => {
  const r = T.analyze('urgent '.repeat(5000));
  assert.ok(r.score <= 100);
});
check('hostile html is returned as plain text only', () => {
  const r = T.analyze('<img src=x onerror=alert(1)> verify your account urgently');
  assert.ok(r.reasons.length > 0);
});

console.log(`\n${passed} passed, ${failures} failed`);
process.exit(failures ? 1 : 0);
