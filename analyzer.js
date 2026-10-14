/*
 * Threat Check analyzer.
 * Rule-based detection for suspicious links and messages.
 * Runs entirely in the browser (or Node, for tests). No network calls.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) {
    module.exports = factory();
  } else {
    root.ThreatCheck = factory();
  }
}(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var MAX_INPUT = 10000;
  var MAX_LINKS = 10;

  /* ---------- Reference data ---------- */

  // Well known brands and the domains they really use. Deliberately small and
  // explicit. A brand used on a domain that is not listed is flagged, so add
  // genuine domains here to avoid false alarms.
  var BRANDS = [
    { name: 'paypal', display: 'PayPal', terms: ['paypal'], domains: ['paypal.com', 'paypal.me'] },
    { name: 'amazon', display: 'Amazon', terms: ['amazon'], domains: ['amazon.com', 'amazon.in', 'amazon.co.uk', 'amazon.de', 'amazon.ca', 'amazon.com.au', 'amazonaws.com', 'amazon.jobs'] },
    { name: 'google', display: 'Google', terms: ['google'], domains: ['google.com', 'google.co.in', 'google.co.uk', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'youtube.com', 'goo.gl'] },
    { name: 'microsoft', display: 'Microsoft', terms: ['microsoft'], domains: ['microsoft.com', 'live.com', 'outlook.com', 'office.com', 'office365.com', 'microsoftonline.com', 'windows.com', 'azure.com', 'sharepoint.com', 'bing.com', 'skype.com'] },
    { name: 'apple', display: 'Apple', terms: ['apple', 'icloud'], domains: ['apple.com', 'icloud.com'] },
    { name: 'netflix', display: 'Netflix', terms: ['netflix'], domains: ['netflix.com'] },
    { name: 'facebook', display: 'Facebook', terms: ['facebook'], domains: ['facebook.com', 'fb.com', 'messenger.com'] },
    { name: 'instagram', display: 'Instagram', terms: ['instagram'], domains: ['instagram.com'] },
    { name: 'whatsapp', display: 'WhatsApp', terms: ['whatsapp'], domains: ['whatsapp.com', 'whatsapp.net'] },
    { name: 'linkedin', display: 'LinkedIn', terms: ['linkedin'], domains: ['linkedin.com', 'lnkd.in'] },
    { name: 'dropbox', display: 'Dropbox', terms: ['dropbox'], domains: ['dropbox.com'] },
    { name: 'docusign', display: 'DocuSign', terms: ['docusign'], domains: ['docusign.com', 'docusign.net'] },
    { name: 'adobe', display: 'Adobe', terms: ['adobe'], domains: ['adobe.com'] },
    { name: 'chase', display: 'Chase', terms: ['chase bank', 'chase'], domains: ['chase.com'] },
    { name: 'wellsfargo', display: 'Wells Fargo', terms: ['wells fargo', 'wellsfargo'], domains: ['wellsfargo.com'] },
    { name: 'bankofamerica', display: 'Bank of America', terms: ['bank of america', 'bankofamerica'], domains: ['bankofamerica.com'] },
    { name: 'citibank', display: 'Citibank', terms: ['citibank'], domains: ['citibank.com', 'citi.com'] },
    { name: 'hdfcbank', display: 'HDFC Bank', terms: ['hdfc bank', 'hdfcbank'], domains: ['hdfcbank.com'] },
    { name: 'icicibank', display: 'ICICI Bank', terms: ['icici bank', 'icicibank'], domains: ['icicibank.com'] },
    { name: 'paytm', display: 'Paytm', terms: ['paytm'], domains: ['paytm.com'] },
    { name: 'phonepe', display: 'PhonePe', terms: ['phonepe'], domains: ['phonepe.com'] },
    { name: 'flipkart', display: 'Flipkart', terms: ['flipkart'], domains: ['flipkart.com'] },
    { name: 'fedex', display: 'FedEx', terms: ['fedex'], domains: ['fedex.com'] },
    { name: 'dhl', display: 'DHL', terms: ['dhl'], domains: ['dhl.com'] },
    { name: 'usps', display: 'USPS', terms: ['usps'], domains: ['usps.com'] },
    { name: 'coinbase', display: 'Coinbase', terms: ['coinbase'], domains: ['coinbase.com'] },
    { name: 'binance', display: 'Binance', terms: ['binance'], domains: ['binance.com'] },
    { name: 'spotify', display: 'Spotify', terms: ['spotify'], domains: ['spotify.com'] }
  ];

  var OFFICIAL = {};
  BRANDS.forEach(function (b) {
    b.domains.forEach(function (d) { OFFICIAL[d] = b.name; });
  });

  var SHORTENERS = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc', 'rb.gy', 'bit.do', 'lnkd.in', 's.id', 't.ly'];

  var RISKY_TLDS = ['xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'zip', 'mov', 'work',
    'support', 'country', 'loan', 'rest', 'icu', 'cyou', 'buzz', 'monster', 'sbs', 'cfd'];

  // Used to decide whether a bare word like "example.com" inside a message is a link.
  var LINK_TLDS = ['com', 'net', 'org', 'info', 'biz', 'io', 'co', 'in', 'us', 'uk', 'de', 'ru', 'cn',
    'ly', 'gl', 'cc', 'ws', 'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'link', 'site',
    'online', 'shop', 'store', 'support', 'help', 'live', 'app', 'dev', 'icu', 'buzz', 'work', 'zip',
    'mov', 'loan', 'country', 'rest', 'cyou', 'page', 'cloud', 'tech', 'vip', 'fun', 'club', 'monster',
    'sbs', 'cfd'];

  var MULTI_PART_TLDS = ['co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'com.au', 'net.au', 'org.au', 'co.in',
    'net.in', 'org.in', 'ac.in', 'gov.in', 'co.jp', 'co.nz', 'com.br', 'com.cn', 'com.mx', 'co.za',
    'com.sg', 'com.hk', 'com.tr', 'com.pk', 'com.bd', 'com.ng'];

  var URL_KEYWORDS = ['login', 'log-in', 'signin', 'sign-in', 'verify', 'verification', 'secure',
    'account', 'update', 'confirm', 'password', 'wallet', 'billing', 'banking', 'suspend', 'unlock',
    'recover', 'invoice', 'payment', 'support'];

  var BRAND_KEYWORDS = ['secure', 'login', 'verify', 'support', 'account', 'update', 'help', 'service',
    'services', 'pay', 'billing', 'wallet', 'id', 'online', 'alert', 'security', 'care', 'team', 'customer'];

  var EXECUTABLE_EXT = /\.(exe|apk|scr|msi|bat|cmd|js|jar|vbs|iso|dmg|zip|rar|ps1)$/i;

  /* ---------- Helpers ---------- */

  function levenshtein(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    var prev = [];
    var i, j;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      var cur = [i];
      for (j = 1; j <= b.length; j++) {
        var cost = a.charAt(i - 1) === b.charAt(j - 1) ? 0 : 1;
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      }
      prev = cur;
    }
    return prev[b.length];
  }

  function registrableDomain(host) {
    var labels = host.split('.');
    if (labels.length <= 2) return host;
    var lastTwo = labels.slice(-2).join('.');
    if (MULTI_PART_TLDS.indexOf(lastTwo) !== -1) return labels.slice(-3).join('.');
    return lastTwo;
  }

  // Candidate "what the attacker meant to write" strings for a domain label.
  function lookalikeVariants(label) {
    var out = [];
    function push(s) { if (out.indexOf(s) === -1) out.push(s); }
    function digits(s, one) {
      return s.replace(/0/g, 'o').replace(/3/g, 'e').replace(/4/g, 'a').replace(/5/g, 's').replace(/1/g, one);
    }
    [label, digits(label, 'l'), digits(label, 'i')].forEach(function (s) {
      push(s);
      push(s.replace(/rn/g, 'm').replace(/vv/g, 'w'));
    });
    return out;
  }

  function levelFor(score) {
    if (score >= 75) return 'critical';
    if (score >= 50) return 'high';
    if (score >= 25) return 'medium';
    return 'low';
  }

  var LEVEL_LABELS = { low: 'Low risk', medium: 'Medium risk', high: 'High risk', critical: 'Critical risk' };

  var LEVEL_SUMMARIES = {
    low: 'No strong warning signs were found. This does not prove the link or message is safe.',
    medium: 'Some warning signs were found. Treat this with caution and verify it through an official channel.',
    high: 'Several warning signs were found that match common phishing and scam patterns.',
    critical: 'This is a strong match for phishing or scam patterns. Do not interact with it.'
  };

  var BASE_RECOMMENDATIONS = {
    low: [
      'Even with a low rating, avoid entering passwords or payment details unless you reached the site by typing its address yourself.'
    ],
    medium: [
      'Do not use the link or phone number in the message. Open the organization\'s official site by typing its address, or use a bookmark you saved earlier.',
      'Contact the sender through an address or number you already trust and ask whether they sent it.'
    ],
    high: [
      'Do not click the link, open attachments, or reply.',
      'Do not enter passwords, one-time codes, or card details.',
      'Report it as phishing in your email or messaging app, then delete it.'
    ],
    critical: [
      'Do not click the link, open attachments, or reply.',
      'Do not enter passwords, one-time codes, or card details.',
      'Report it as phishing in your email or messaging app, then delete it.',
      'If you already clicked or shared details, change the affected passwords now and contact your bank or the service provider.'
    ]
  };

  var LIMITS = 'This check looks only at the text you paste. It cannot see how old a domain is, whether the site has a valid certificate, where a link redirects, or whether the address appears on a blocklist. Those checks need a server, and this tool does not send what you paste anywhere.';

  function finding(id, points, title, detail, tip) {
    return { id: id, points: points, title: title, detail: detail, tip: tip || null };
  }

  function sum(list) {
    return list.reduce(function (t, f) { return t + f.points; }, 0);
  }

  /* ---------- URL analysis ---------- */

  function parseUrl(raw) {
    var s = raw.trim();
    var hasScheme = /^[a-z][a-z0-9+.\-]*:\/\//i.test(s);
    var odd = /^(javascript|data|vbscript|file):/i.test(s);
    var withScheme = (hasScheme || odd) ? s : 'https://' + s;
    try {
      return { url: new URL(withScheme), assumedScheme: !(hasScheme || odd), source: withScheme };
    } catch (e) {
      return null;
    }
  }

  function brandChecks(host, registrable) {
    var labels = host.split('.');
    var regLabels = registrable.split('.');
    var subLabels = labels.slice(0, labels.length - regLabels.length);
    var label = regLabels[0];
    var variants = lookalikeVariants(label);
    var best = null;

    function consider(points, title, detail, tip) {
      if (!best || points > best.points) best = finding('brand', points, title, detail, tip);
    }

    BRANDS.forEach(function (brand) {
      var b = brand.name;
      var shown = brand.display;

      if (label === b) {
        consider(25, 'Uses the ' + shown + ' name on a domain that is not recognized as official',
          'The domain "' + registrable + '" contains the name ' + shown + ', but it is not one of the domains we know ' + shown + ' uses.',
          'Go to ' + shown + ' by typing its official address yourself instead of following the link.');
        return;
      }

      // Number or letter swaps such as paypa1 or arnazon.
      var swapped = variants.some(function (v) { return v !== label && v === b; });
      if (swapped) {
        consider(40, 'Imitates ' + shown + ' with swapped characters',
          'The domain "' + registrable + '" looks like "' + b + '" with look-alike characters substituted.',
          'Check the address letter by letter. Scammers swap characters such as 1 for l or rn for m.');
        return;
      }

      // Small typing differences such as amazom.
      var maxDist = b.length >= 9 ? 2 : (b.length >= 6 ? 1 : 0);
      if (maxDist > 0 && Math.abs(label.length - b.length) <= maxDist && levenshtein(label, b) <= maxDist) {
        consider(35, 'Looks like a misspelling of ' + shown,
          'The domain name "' + label + '" is only a character or two away from "' + b + '".',
          'Check the address letter by letter before trusting it.');
        return;
      }

      // Brand plus an added word, such as paypal-secure.
      if (b.length >= 5) {
        var embedded = variants.some(function (v) {
          if (v.split('-').indexOf(b) !== -1) return true;
          return BRAND_KEYWORDS.some(function (k) { return v === b + k || v === k + b; });
        });
        if (embedded) {
          consider(30, 'Combines the ' + shown + ' name with extra words',
            'The domain "' + registrable + '" builds on the name ' + shown + ' but is not a domain ' + shown + ' uses.',
            'Real companies rarely put words like "secure" or "login" into a separate domain. Go to the official site directly.');
          return;
        }
      }

      // Brand shown in the subdomain, real domain is something else.
      var inSub = subLabels.some(function (l) { return l === b || (b.length >= 5 && l.indexOf(b) !== -1); });
      if (inSub) {
        consider(35, 'Puts the ' + shown + ' name in front of a different domain',
          'The address starts with ' + shown + ' but the real domain is "' + registrable + '". Only the last part of the host decides where the link goes.',
          'Read the host from right to left. The part just before the domain ending is the real owner.');
      }
    });

    return best;
  }

  function analyzeUrl(input) {
    var parsed = parseUrl(input);
    if (!parsed) return { error: 'invalid-url' };
    var u = parsed.url;
    var found = [];
    var add = function (f) { if (f) found.push(f); };
    var proto = u.protocol;

    // Script and data URLs can run code or hide content.
    if (/^(javascript|data|vbscript):$/.test(proto)) {
      add(finding('scheme', 70, 'Uses a "' + proto.replace(':', '') + '" address instead of a website',
        'This is not a normal web address. It can run code or show content that is built into the link itself.',
        'Never open links that begin with "javascript:" or "data:".'));
      return { input: input, normalized: u.href, host: '', score: 70, findings: found };
    }
    if (proto !== 'http:' && proto !== 'https:') {
      add(finding('scheme', 15, 'Uses an unusual address type (' + proto.replace(':', '') + ')',
        'Most legitimate links start with http or https.', null));
    }

    var host = u.hostname.toLowerCase();
    var isIPv4 = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    var isIPv6 = host.charAt(0) === '[';
    var isIP = isIPv4 || isIPv6;
    var registrable = isIP ? host : registrableDomain(host);
    var official = !isIP && Object.prototype.hasOwnProperty.call(OFFICIAL, registrable);

    if (proto === 'http:' && !parsed.assumedScheme) {
      add(finding('http', 10, 'Does not use HTTPS',
        'The address starts with http, so the connection is not encrypted. Login pages on such addresses are a warning sign.',
        null));
    }

    if (isIP) {
      add(finding('ip', 35, 'Uses an IP address instead of a domain name',
        'The address points to "' + host + '" directly. Legitimate services almost always use a named domain.',
        'Do not enter any details on a page reached through a raw IP address.'));
      var afterScheme = parsed.source.replace(/^[a-z][a-z0-9+.\-]*:\/\//i, '');
      var authority = afterScheme.split(/[\/?#]/)[0];
      authority = authority.slice(authority.lastIndexOf('@') + 1).replace(/:\d+$/, '').toLowerCase();
      if (isIPv4 && authority !== host) {
        add(finding('ip-hidden', 10, 'The IP address is written in a disguised form',
          'The address was written as "' + authority + '" but resolves to ' + host + '. Disguised numbers are used to get past quick visual checks.', null));
      }
    }

    if (u.username) {
      var domainLike = u.username.indexOf('.') !== -1;
      add(finding('userinfo', domainLike ? 30 : 15, 'Has a username section before the real address',
        'Everything before the "@" is ignored when the link is opened. The real destination is "' + host + '".',
        'Read what comes after the "@". That is where the link really goes.'));
    }

    if (host.split('.').some(function (l) { return l.indexOf('xn--') === 0; })) {
      add(finding('punycode', 25, 'Uses look-alike (internationalized) characters',
        'The domain contains characters from other alphabets that can look identical to ordinary letters.',
        'Type the site\'s address yourself instead of following the link.'));
    }

    if (!isIP && (SHORTENERS.indexOf(host) !== -1 || SHORTENERS.indexOf(registrable) !== -1)) {
      add(finding('shortener', 15, 'Uses a link shortener',
        '"' + registrable + '" hides the real destination behind a short code.',
        'Expand the link with a preview feature, or ask the sender for the full address.'));
    }

    if (!isIP) {
      var labelCount = host.split('.').length;
      var regCount = registrable.split('.').length;
      if (labelCount - regCount >= 3) {
        add(finding('subdomains', 10, 'Has many subdomains',
          'The host "' + host + '" has ' + (labelCount - regCount) + ' parts in front of the main domain, which can be used to bury the real name.', null));
      }
      var hyphens = (host.match(/-/g) || []).length;
      if (hyphens >= 2) {
        add(finding('hyphens', 8, 'Has several hyphens in the domain',
          'Domains with several hyphens are common in throwaway scam sites.', null));
      }
      var tld = registrable.slice(registrable.indexOf('.') + 1);
      if (!official && RISKY_TLDS.indexOf(tld) !== -1) {
        add(finding('tld', 12, 'Uses a domain ending often seen in scams',
          'The ending ".' + tld + '" is cheap or free to register and is overrepresented in phishing campaigns.', null));
      }
      if (!official) {
        var b = brandChecks(host, registrable);
        add(b);
      }
    }

    if (u.port && u.port !== '80' && u.port !== '443') {
      add(finding('port', 8, 'Uses an unusual port number',
        'The address connects on port ' + u.port + ', which ordinary websites do not need to show.', null));
    }

    if (!official) {
      var haystack = (host + ' ' + decodeURIComponentSafe(u.pathname)).toLowerCase();
      var hits = URL_KEYWORDS.filter(function (k) { return haystack.indexOf(k) !== -1; });
      if (hits.length) {
        var shown = hits.slice(0, 4);
        add(finding('keywords', Math.min(12, hits.length * 6), 'Contains sensitive words in the address',
          'Found: ' + shown.join(', ') + '. Scam pages often use words like these to look official.', null));
      }
    }

    var redirect = false;
    u.searchParams.forEach(function (value) {
      if (/^https?:\/\//i.test(value) || /^\/\//.test(value)) redirect = true;
    });
    if (redirect) {
      add(finding('redirect-param', 10, 'Contains another web address inside it',
        'A second address is passed as a parameter. This pattern is used to bounce visitors to a different site.', null));
    }

    if (input.trim().length > 100) {
      add(finding('long', 5, 'Is unusually long',
        'Very long addresses can hide the important part from a quick glance.', null));
    }

    if ((input.match(/%[0-9a-f]{2}/gi) || []).length > 5) {
      add(finding('encoded', 5, 'Contains many encoded characters',
        'Heavy percent-encoding can be used to disguise what the address contains.', null));
    }

    if (EXECUTABLE_EXT.test(u.pathname)) {
      add(finding('download', 20, 'Points to a file that can run or install software',
        'The address ends in a file type commonly used to deliver malware.',
        'Do not download or open files from links you did not expect.'));
    }

    var score = Math.min(100, sum(found));
    return { input: input, normalized: u.href, host: host, score: score, findings: found };
  }

  function decodeURIComponentSafe(s) {
    try { return decodeURIComponent(s); } catch (e) { return s; }
  }

  /* ---------- Link extraction ---------- */

  function trimTrailing(s) {
    return s.replace(/[.,;:!?)\]}'"]+$/, '');
  }

  function extractUrls(text) {
    var urls = [];
    var ranges = [];
    var m;
    var explicit = /\b(?:https?:\/\/|www\.)[^\s<>"'`]+/gi;
    while ((m = explicit.exec(text)) !== null) {
      ranges.push([m.index, m.index + m[0].length]);
      urls.push(trimTrailing(m[0]));
    }
    var bare = /\b(?:[a-z0-9](?:[a-z0-9\-]*[a-z0-9])?\.)+([a-z]{2,24})(?:\/[^\s<>"'`]*)?/gi;
    while ((m = bare.exec(text)) !== null) {
      var start = m.index;
      var inside = ranges.some(function (r) { return start >= r[0] && start < r[1]; });
      if (inside) continue;
      if (start > 0 && text.charAt(start - 1) === '@') continue; // email address
      var candidate = trimTrailing(m[0]);
      var tld = m[1].toLowerCase();
      if (LINK_TLDS.indexOf(tld) === -1) continue;
      urls.push(candidate);
    }
    var seen = {};
    return urls.filter(function (u) {
      var k = u.toLowerCase();
      if (seen[k]) return false;
      seen[k] = true;
      return true;
    });
  }

  /* ---------- Message analysis ---------- */

  var NEGATION_BEFORE = /(never|not|n't|no one should)\s+(\w+\s+)?(share|give|disclose|reveal|send|provide|tell|ask)\b/;

  var MESSAGE_RULES = [
    {
      id: 'urgency', points: 10, title: 'Pressures you to act quickly',
      detail: 'Scams create a deadline so you act before thinking.',
      tip: 'Pause. Real organizations do not require instant action through a link or message.',
      re: /\b(urgent(ly)?|immediately|right away|act now|final notice|last (chance|warning)|expires? (today|soon|in \d+)|within \d+ ?(hours?|hrs?|minutes?|mins?|days?)|as soon as possible|asap|time[- ]sensitive)(?!\w)/gi
    },
    {
      id: 'threat', points: 12, title: 'Threatens consequences such as a locked account',
      detail: 'Fear of losing access or facing penalties is a common way to push people into acting.',
      tip: 'Log in to the service by typing its address yourself to check whether anything is actually wrong.',
      re: /\b(account (has been |was |will be |is )?(suspended|locked|closed|limited|disabled|blocked|compromised|terminated|deactivated)|unusual (sign[- ]?in|login|activity)|suspicious (activity|login|sign[- ]?in|transaction)|unauthori[sz]ed (access|transaction|login|activity)|legal action|will be (arrested|prosecuted)|arrest warrant|you will lose access)(?!\w)/gi
    },
    {
      id: 'credentials', points: 20, negatable: true, title: 'Asks for passwords, codes, or personal details',
      detail: 'Legitimate organizations do not ask for these by message or through a link.',
      tip: 'Never share one-time codes, PINs, passwords, or card details with anyone who contacts you.',
      re: /\b(passwords?|passcode|your pin|pin (number|code)|otp|one[- ]time (password|passcode|code)|cvv|cvc|card (number|details)|security code|ssn|social security|aadhaar|pan card|bank (account )?details|login (details|credentials)|verify your (account|identity|details|information)|confirm your (account|identity|details|information|password)|update your (payment|billing|account|card) (details|information|info))(?!\w)/gi
    },
    {
      id: 'prize', points: 15, title: 'Promises a prize, reward, or refund',
      detail: 'Unexpected winnings and refunds are used as bait.',
      tip: 'If you did not enter a contest or expect a refund, assume it is not real.',
      re: /\b(you(?:'ve| have)? (won|been selected|are a winner)|congratulations[,!]? you|lottery|claim your (prize|reward|gift|refund)|free (gift|iphone|prize|money)|cash prize|jackpot|refund (is )?(pending|waiting|available))(?!\w)/gi
    },
    {
      id: 'payment', points: 15, title: 'Mentions hard-to-trace payment or upfront fees',
      detail: 'Gift cards, crypto, wire transfers and "small fees" are favored because the money cannot be recovered.',
      tip: 'Never pay a fee or send gift cards or crypto to claim something or to resolve a problem.',
      re: /\b(gift cards?|itunes card|google play card|wire transfer|western union|moneygram|bitcoin|btc|crypto(currency)?|usdt|processing fee|customs fee|delivery fee|release fee|advance fee|upfront fee|transfer (the )?(money|funds)|pay (a |the )?(small )?fee)(?!\w)/gi
    },
    {
      id: 'greeting', points: 6, title: 'Uses a generic greeting',
      detail: 'Messages from a service you use usually address you by name.', tip: null,
      re: /\bdear (customer|user|member|client|account holder|valued (customer|member)|sir\/madam|sir or madam|beneficiary)(?!\w)/gi
    },
    {
      id: 'click', points: 8, title: 'Tells you to click a link or open an attachment',
      detail: 'Phishing messages push you toward a link or file.',
      tip: 'Type the website address yourself instead of clicking.',
      re: /\b(click (here|the link|below|on the link)|tap (here|the link|below)|follow (this|the) link|open (the )?(attachment|link)|log ?in (here|now))(?!\w)/gi
    },
    {
      id: 'secrecy', points: 10, title: 'Asks you to keep it secret',
      detail: 'Secrecy stops you from checking with someone who might spot the scam.',
      tip: 'Talk to a friend, family member, or the organization directly before acting.',
      re: /\b(do not tell|don'?t tell|keep (this|it) (secret|confidential|private)|tell no one|do not (share|discuss) this)(?!\w)/gi
    },
    {
      id: 'remote', points: 15, title: 'Mentions remote access or installing software',
      detail: 'Scammers ask you to install tools that give them control of your device.',
      tip: 'Never install software or give remote access because of an unsolicited message or call.',
      re: /\b(anydesk|teamviewer|ultraviewer|quick ?support|remote (access|desktop)|install (the )?(app|software|apk))(?!\w)/gi
    },
    {
      id: 'authority', points: 8, title: 'Claims to be an authority or a delivery problem',
      detail: 'Police, tax, customs and courier messages are often imitated.', tip: null,
      re: /\b(irs|income tax department|customs|police|cbi|social security administration|tax refund|undelivered (package|parcel)|missed delivery|delivery attempt|your (package|parcel) (is|has been) (held|on hold))(?!\w)/gi
    },
    {
      id: 'callback', points: 8, title: 'Asks you to call or message a number',
      detail: 'Callback numbers in unexpected messages lead to scam call centers.',
      tip: 'Look up the organization\'s number from its official site or a card you already have.',
      re: /\b(call|contact|whatsapp|text|message)\b[^.\n]{0,25}\+?\d[\d\s\-()]{8,}\d/gi
    }
  ];

  function findMatches(text, rule) {
    var rx = new RegExp(rule.re.source, rule.re.flags);
    var phrases = [];
    var m;
    while ((m = rx.exec(text)) !== null) {
      if (m[0].length === 0) { rx.lastIndex++; continue; }
      if (rule.negatable) {
        var before = text.slice(Math.max(0, m.index - 40), m.index).toLowerCase();
        if (NEGATION_BEFORE.test(before)) continue;
      }
      var phrase = m[0].toLowerCase().replace(/\s+/g, ' ');
      if (phrases.indexOf(phrase) === -1) phrases.push(phrase);
      if (phrases.length >= 4) break;
    }
    return phrases;
  }

  function analyzeMessage(text) {
    var found = [];
    var matched = {};

    MESSAGE_RULES.forEach(function (rule) {
      var phrases = findMatches(text, rule);
      if (phrases.length) {
        matched[rule.id] = true;
        found.push(finding(rule.id, rule.points, rule.title,
          rule.detail + ' Found: ' + phrases.map(function (p) { return '"' + p + '"'; }).join(', ') + '.', rule.tip));
      }
    });

    var letters = text.replace(/[^A-Za-z]/g, '');
    var upper = text.replace(/[^A-Z]/g, '');
    if ((letters.length >= 20 && upper.length / letters.length > 0.4) || /!{3,}/.test(text)) {
      found.push(finding('shouting', 6, 'Uses shouting or heavy emphasis',
        'Long stretches of capitals or repeated exclamation marks are used to create alarm.', null));
    }

    // Links
    var urls = extractUrls(text).slice(0, MAX_LINKS);
    var links = [];
    urls.forEach(function (raw) {
      var r = analyzeUrl(raw);
      if (r.error) return;
      links.push({
        url: raw,
        host: r.host,
        score: r.score,
        level: levelFor(r.score),
        reasons: r.findings
      });
    });

    // Combination: pressure + request + link.
    if (links.length && matched.urgency && (matched.credentials || matched.payment || matched.threat)) {
      found.push(finding('combo', 10, 'Combines pressure, a request, and a link',
        'Urgency, a demand for action or details, and a link together are the typical shape of a phishing message.', null));
    }

    // A brand is named but a link goes elsewhere.
    var lower = text.toLowerCase();
    var mismatch = null;
    BRANDS.forEach(function (brand) {
      if (mismatch) return;
      var mentioned = brand.terms.some(function (t) {
        return new RegExp('\\b' + t.replace(/ /g, '\\s+') + '\\b', 'i').test(lower);
      });
      if (!mentioned) return;
      for (var i = 0; i < links.length; i++) {
        var l = links[i];
        if (!l.host || /^\d|^\[/.test(l.host)) { mismatch = { brand: brand, link: l }; return; }
        var reg = registrableDomain(l.host);
        if (brand.domains.indexOf(reg) === -1 && !Object.prototype.hasOwnProperty.call(OFFICIAL, reg)) {
          mismatch = { brand: brand, link: l };
          return;
        }
      }
    });
    if (mismatch) {
      found.push(finding('brand-mismatch', 15, 'Names ' + mismatch.brand.display + ' but links somewhere else',
        'The message mentions ' + mismatch.brand.display + ', but the link goes to "' + (mismatch.link.host || mismatch.link.url) + '".',
        'Go to ' + mismatch.brand.display + ' by typing its official address yourself.'));
    }

    var maxLink = links.reduce(function (m, l) { return Math.max(m, l.score); }, 0);
    var score = Math.min(100, sum(found) + maxLink);
    return { score: score, findings: found, links: links, maxLink: maxLink };
  }

  /* ---------- Entry points ---------- */

  function detectType(text) {
    var t = text.trim();
    if (/\s/.test(t)) return 'message';
    if (/^[a-z][a-z0-9+.\-]*:\/\//i.test(t)) return 'url';
    if (/^(javascript|data|vbscript):/i.test(t)) return 'url';
    if (/^\d{1,3}(\.\d{1,3}){3}([\/:?#]|$)/.test(t)) return 'url';
    if (/^[^\s\/@]+\.[a-z]{2,24}([\/:?#]|$)/i.test(t)) return 'url';
    return 'message';
  }

  function recommendationsFor(level, findings) {
    var list = BASE_RECOMMENDATIONS[level].slice();
    findings.forEach(function (f) {
      if (f.tip && list.indexOf(f.tip) === -1) list.push(f.tip);
    });
    return list.slice(0, 7);
  }

  function analyze(input) {
    var text = String(input == null ? '' : input).trim();
    if (!text) return { error: 'empty' };
    if (text.length > MAX_INPUT) text = text.slice(0, MAX_INPUT);

    var type = detectType(text);
    var score, reasons, links = [];

    if (type === 'url') {
      var r = analyzeUrl(text);
      if (r.error) return { error: 'invalid-url' };
      score = r.score;
      reasons = r.findings;
    } else {
      var m = analyzeMessage(text);
      score = m.score;
      reasons = m.findings;
      links = m.links;
    }

    var level = levelFor(score);
    var all = reasons.slice();
    links.forEach(function (l) { all = all.concat(l.reasons); });

    return {
      type: type,
      score: score,
      level: level,
      label: LEVEL_LABELS[level],
      summary: LEVEL_SUMMARIES[level],
      reasons: reasons,
      links: links,
      recommendations: recommendationsFor(level, all),
      limits: LIMITS
    };
  }

  return {
    analyze: analyze,
    analyzeUrl: analyzeUrl,
    analyzeMessage: analyzeMessage,
    extractUrls: extractUrls,
    detectType: detectType,
    levelFor: levelFor,
    levenshtein: levenshtein,
    registrableDomain: registrableDomain
  };
}));
