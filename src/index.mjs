import http from 'node:http';
import https from 'node:https';
import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import dns from 'node:dns/promises';
import net from 'node:net';
import { URL } from 'node:url';

export const SUPPORTED_SERVICES = new Set(['x', 'mastodon', 'bluesky', 'misskey', 'threads']);

export const SERVICE_LABELS = {
  x: 'X',
  mastodon: 'Mastodon',
  bluesky: 'Bluesky',
  misskey: 'Misskey',
  threads: 'Threads',
};

export const SERVICE_LIMITS = {
  x: 280,
  mastodon: 500,
  bluesky: 300,
  threads: 500,
  misskey: 3000,
};

export function countServiceCharacters(service, text) {
  const str = String(text || '');
  if (service === 'x') {
    // X Twitter: CJK / fullwidth = 2, ASCII = 1, URLs = 23
    let count = 0;
    const urlRegex = /https?:\/\/[^\s]+/g;
    const cleanText = str.replace(urlRegex, () => {
      count += 23;
      return '';
    });
    for (const char of cleanText) {
      const code = char.codePointAt(0);
      if (
        (code >= 0x1100 && code <= 0x115f) ||
        (code >= 0x2e80 && code <= 0xa4cf) ||
        (code >= 0xac00 && code <= 0xd7a3) ||
        (code >= 0xf900 && code <= 0xfaff) ||
        (code >= 0xfe10 && code <= 0xfe19) ||
        (code >= 0xfe30 && code <= 0xfe6f) ||
        (code >= 0xff00 && code <= 0xff60) ||
        (code >= 0xffe0 && code <= 0xffe6) ||
        (code >= 0x20000 && code <= 0x2fffd) ||
        (code >= 0x30000 && code <= 0x3fffd)
      ) {
        count += 2;
      } else {
        count += 1;
      }
    }
    return count;
  }

  if (service === 'bluesky') {
    if (typeof Intl !== 'undefined' && Intl.Segmenter) {
      const segmenter = new Intl.Segmenter('en', { granularity: 'grapheme' });
      return Array.from(segmenter.segment(str)).length;
    }
    return Array.from(str).length;
  }

  // Mastodon, Threads, Misskey: Unicode code point count
  return Array.from(str).length;
}

export function splitPostIntoThreads(service, text, options = {}) {
  const limit = SERVICE_LIMITS[service] || 300;
  const numbering = options.numbering !== false;
  const raw = String(text || '').trim();
  if (!raw) return [];

  if (countServiceCharacters(service, raw) <= limit) {
    return [raw];
  }

  const paragraphs = raw.split(/\n\n+/);
  const chunks = [];
  let current = '';

  for (const para of paragraphs) {
    const candidate = current ? `${current}\n\n${para}` : para;
    if (countServiceCharacters(service, candidate) <= limit - (numbering ? 8 : 0)) {
      current = candidate;
    } else {
      if (current) chunks.push(current);
      if (countServiceCharacters(service, para) > limit - (numbering ? 8 : 0)) {
        const sentences = para.split(/(?<=[。．.！？!?\n])\s*/);
        let sub = '';
        for (const s of sentences) {
          const subCand = sub ? `${sub} ${s}` : s;
          if (countServiceCharacters(service, subCand) <= limit - (numbering ? 8 : 0)) {
            sub = subCand;
          } else {
            if (sub) chunks.push(sub);
            if (countServiceCharacters(service, s) > limit - (numbering ? 8 : 0)) {
              let remaining = s;
              while (remaining) {
                let sliceLen = limit - (numbering ? 10 : 0);
                while (sliceLen > 0 && countServiceCharacters(service, remaining.slice(0, sliceLen)) > limit - (numbering ? 10 : 0)) {
                  sliceLen--;
                }
                if (sliceLen <= 0) sliceLen = 1;
                chunks.push(remaining.slice(0, sliceLen));
                remaining = remaining.slice(sliceLen);
              }
              sub = '';
            } else {
              sub = s;
            }
          }
        }
        if (sub) chunks.push(sub);
        current = '';
      } else {
        current = para;
      }
    }
  }
  if (current) chunks.push(current);

  if (!numbering || chunks.length <= 1) {
    return chunks;
  }

  const total = chunks.length;
  return chunks.map((chunk, idx) => `${chunk} (${idx + 1}/${total})`);
}

export function normalizeInstanceUrl(value) {
  const raw = String(value || '').trim();
  if (!raw) return '';
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    throw Object.assign(new Error('インスタンスURLはHTTPS形式で入力してください。'), { statusCode: 400 });
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw Object.assign(new Error('インスタンスURLはHTTPS形式で、認証情報を含めないでください。'), { statusCode: 400 });
  }
  return parsed.origin;
}

export function isUnsafeIpv4(address) {
  const octets = String(address).split('.').map((part) => Number(part));
  if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return false;
  const value = (((octets[0] * 256) + octets[1]) * 256 + octets[2]) * 256 + octets[3];
  const ranges = [
    [0, 0xff000000],          // 0.0.0.0/8
    [0x0a000000, 0xff000000], // 10.0.0.0/8
    [0x64400000, 0xffc00000], // 100.64.0.0/10
    [0x7f000000, 0xff000000], // 127.0.0.0/8
    [0xa9fe0000, 0xffff0000], // 169.254.0.0/16
    [0xac100000, 0xfff00000], // 172.16.0.0/12
    [0xc0000000, 0xffffff00], // 192.0.0.0/24
    [0xc0000200, 0xffffff00], // 192.0.2.0/24
    [0xc0a80000, 0xffff0000], // 192.168.0.0/16
    [0xc6120000, 0xfffe0000], // 198.18.0.0/15
    [0xc6336400, 0xffffff00], // 198.51.100.0/24
    [0xcb007100, 0xffffff00], // 203.0.113.0/24
    [0xe0000000, 0xf0000000], // multicast
    [0xf0000000, 0xf0000000], // reserved
  ];
  return ranges.some(([network, mask]) => ((value & mask) >>> 0) === (network >>> 0));
}

export function parseIpv6(address) {
  let value = String(address).toLowerCase().split('%')[0];
  if (value.includes('.')) {
    const lastColon = value.lastIndexOf(':');
    if (lastColon < 0) return null;
    const octets = value.slice(lastColon + 1).split('.').map(Number);
    if (octets.length !== 4 || octets.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return null;
    const ipv4Hex = `${((octets[0] << 8) | octets[1]).toString(16)}:${((octets[2] << 8) | octets[3]).toString(16)}`;
    value = `${value.slice(0, lastColon)}:${ipv4Hex}`;
  }
  const halves = value.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - left.length - right.length;
  if (missing < (halves.length === 2 ? 1 : 0)) return null;
  const groups = [...left, ...Array(missing).fill('0'), ...right];
  if (groups.length !== 8 || groups.some((part) => !/^[0-9a-f]{1,4}$/.test(part))) return null;
  return groups.map((part) => Number.parseInt(part, 16));
}

export function isUnsafeAddress(address) {
  const normalized = String(address || '').toLowerCase().replace(/^\[|\]$/g, '').split('%')[0];
  if (net.isIP(normalized) === 4) return isUnsafeIpv4(normalized);
  if (net.isIP(normalized) !== 6) return true;
  const groups = parseIpv6(normalized);
  if (!groups) return true;
  const first = groups[0];
  const bytes = groups.flatMap((group) => [(group >> 8) & 0xff, group & 0xff]);
  const mappedIpv4 = bytes.slice(0, 10).every((byte) => byte === 0) && bytes[10] === 0xff && bytes[11] === 0xff;
  if (mappedIpv4) return true;
  const isGlobalUnicast = (first & 0xe000) === 0x2000;
  const isProtocolAssignment = groups[0] === 0x2001 && (groups[1] & 0xfe00) === 0;
  const isSixToFour = groups[0] === 0x2002;
  const isDocumentation = (groups[0] === 0x2001 && groups[1] === 0x0db8)
    || (groups[0] === 0x3fff && (groups[1] & 0xf000) === 0);
  return !isGlobalUnicast
    || isProtocolAssignment
    || isSixToFour
    || isDocumentation
    || (first & 0xfe00) === 0xfc00
    || (first & 0xffc0) === 0xfe80;
}

export const createPinnedAddressLookup = (address) => (_hostname, options, callback) =>
  options?.all
    ? callback(null, [{ address, family: net.isIP(address) }])
    : callback(null, address, net.isIP(address));

export async function resolveSafeExternalUrl(rawUrl) {
  let parsed;
  try {
    parsed = new URL(String(rawUrl));
  } catch {
    throw Object.assign(new Error('外部URLが不正です。'), { statusCode: 400 });
  }
  if (parsed.protocol !== 'https:' || parsed.username || parsed.password) {
    throw Object.assign(new Error('外部URLはHTTPS形式で、認証情報を含めないでください。'), { statusCode: 400 });
  }
  const hostname = parsed.hostname.replace(/^\[|\]$/g, '').toLowerCase();
  if (
    !hostname ||
    hostname === 'localhost' ||
    hostname.endsWith('.localhost') ||
    hostname.endsWith('.local') ||
    hostname.endsWith('.internal') ||
    hostname === 'metadata.google.internal' ||
    hostname === 'instance-data.ec2.internal' ||
    hostname === 'host.docker.internal'
  ) {
    throw Object.assign(new Error('内部ネットワーク向けのURLは利用できません。'), { statusCode: 400 });
  }
  let addresses;
  try {
    addresses = net.isIP(hostname) ? [{ address: hostname }] : await dns.lookup(hostname, { all: true, verbatim: true });
  } catch {
    throw Object.assign(new Error('外部URLのホストを解決できません。'), { statusCode: 400 });
  }
  if (!addresses.length || addresses.some(({ address }) => isUnsafeAddress(address))) {
    throw Object.assign(new Error('内部ネットワーク向けのURLは利用できません。'), { statusCode: 400 });
  }
  return { parsed, address: addresses[0].address };
}

export async function assertSafeExternalUrl(rawUrl) {
  const { parsed } = await resolveSafeExternalUrl(rawUrl);
  return parsed;
}

export function encryptCredentials(value, key) {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(value), 'utf8'), cipher.final()]);
  return `v1.${iv.toString('base64url')}.${cipher.getAuthTag().toString('base64url')}.${encrypted.toString('base64url')}`;
}

export function decryptCredentials(value, key) {
  const [version, ivEncoded, tagEncoded, payloadEncoded] = String(value || '').split('.');
  if (version !== 'v1' || !ivEncoded || !tagEncoded || !payloadEncoded) throw new Error('暗号化データが不正です。');
  const decipher = createDecipheriv('aes-256-gcm', key, Buffer.from(ivEncoded, 'base64url'));
  decipher.setAuthTag(Buffer.from(tagEncoded, 'base64url'));
  const payload = Buffer.concat([decipher.update(Buffer.from(payloadEncoded, 'base64url')), decipher.final()]);
  return JSON.parse(payload.toString('utf8'));
}

export function requestExternal(rawUrl, options = {}) {
  return resolveSafeExternalUrl(rawUrl).then(({ parsed, address }) => new Promise((resolve, reject) => {
    const transport = parsed.protocol === 'https:' ? https : http;
    const headers = { ...(options.headers || {}) };
    const body = options.body instanceof URLSearchParams ? options.body.toString() : options.body;
    if (body && !Object.keys(headers).some((key) => key.toLowerCase() === 'content-length')) {
      headers['Content-Length'] = Buffer.byteLength(body);
    }
    const request = transport.request({
      protocol: parsed.protocol,
      hostname: parsed.hostname.replace(/^\[|\]$/g, ''),
      port: parsed.port || undefined,
      path: `${parsed.pathname}${parsed.search}`,
      method: options.method || 'GET',
      headers,
      lookup: createPinnedAddressLookup(address),
      servername: net.isIP(parsed.hostname.replace(/^\[|\]$/g, '')) ? undefined : parsed.hostname,
      signal: options.signal,
    }, (response) => {
      const chunks = [];
      let total = 0;
      response.on('data', (chunk) => {
        total += chunk.length;
        if (total > 2 * 1024 * 1024) {
          request.destroy(new Error('外部APIレスポンスが大きすぎます。'));
          return;
        }
        chunks.push(chunk);
      });
      response.on('end', () => {
        const raw = Buffer.concat(chunks).toString('utf8');
        resolve({ status: response.statusCode || 0, ok: (response.statusCode || 0) >= 200 && (response.statusCode || 0) < 300, text: async () => raw });
      });
      response.on('error', reject);
    });
    request.on('error', reject);
    if (body) request.write(body);
    request.end();
  }));
}

async function fetchJson(url, options = {}) {
  const requester = options.requestImpl || requestExternal;
  const response = await requester(url, { ...options, signal: AbortSignal.timeout(30000) });
  const raw = await response.text();
  let body = null;
  try { body = raw ? JSON.parse(raw) : {}; } catch { body = { raw: raw.slice(0, 500) }; }
  if (!response.ok) {
    const message = body?.error?.message || body?.error || body?.message || `外部APIエラー (${response.status})`;
    throw new Error(String(message).slice(0, 300));
  }
  return body;
}

async function formRequest(url, params, options = {}) {
  return fetchJson(url, {
    ...options,
    method: options.method || 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...(options.headers || {}) },
    body: new URLSearchParams(Object.entries(params).map(([key, value]) => [key, String(value)])),
  });
}

export async function postToService(account, text, options = {}) {
  if (options.dryRun) {
    return { remoteId: `dry_${account.service}_${randomUUID()}`, simulated: true };
  }
  const credentials = account.credentials;
  const reqOpts = options.requestImpl ? { requestImpl: options.requestImpl } : {};
  switch (account.service) {
    case 'x': {
      const payload = { text };
      if (options.replyToId) {
        payload.reply = { in_reply_to_tweet_id: options.replyToId };
      }
      const body = await fetchJson('https://api.x.com/2/tweets', {
        ...reqOpts,
        method: 'POST',
        headers: { Authorization: `Bearer ${credentials.accessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      return { remoteId: body.data?.id || null };
    }
    case 'mastodon': {
      const instanceUrl = normalizeInstanceUrl(account.instanceUrl);
      const form = { status: text };
      if (options.replyToId) {
        form.in_reply_to_id = options.replyToId;
      }
      const body = await formRequest(`${instanceUrl}/api/v1/statuses`, form, { ...reqOpts, headers: { Authorization: `Bearer ${credentials.accessToken}` } });
      return { remoteId: body.id || null };
    }
    case 'misskey': {
      const instanceUrl = normalizeInstanceUrl(account.instanceUrl);
      const payload = { i: credentials.accessToken, text };
      if (options.replyToId) {
        payload.replyId = options.replyToId;
      }
      const body = await fetchJson(`${instanceUrl}/api/notes/create`, {
        ...reqOpts,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      });
      return { remoteId: body.createdNote?.id || null };
    }
    case 'bluesky': {
      const session = await fetchJson('https://bsky.social/xrpc/com.atproto.server.createSession', {
        ...reqOpts,
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ identifier: credentials.username, password: credentials.appPassword }),
      });
      const record = {
        '$type': 'app.bsky.feed.post',
        text,
        createdAt: new Date().toISOString(),
      };
      if (options.replyToId) {
        record.reply = {
          root: { uri: options.replyRoot || options.replyToId, cid: options.replyRootCid || 'bafyreie546fudph4' },
          parent: { uri: options.replyToId, cid: options.replyParentCid || 'bafyreie546fudph4' },
        };
      }
      const postRecord = await fetchJson('https://bsky.social/xrpc/com.atproto.repo.createRecord', {
        ...reqOpts,
        method: 'POST',
        headers: { Authorization: `Bearer ${session.accessJwt}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          repo: session.did || credentials.username,
          collection: 'app.bsky.feed.post',
          record,
        }),
      });
      return { remoteId: postRecord.uri || null };
    }
    case 'threads': {
      const form = { media_type: 'TEXT', text, access_token: credentials.accessToken };
      if (options.replyToId) {
        form.reply_to_id = options.replyToId;
      }
      const container = await formRequest('https://graph.threads.com/v1.0/me/threads', form, reqOpts);
      const published = await formRequest('https://graph.threads.com/v1.0/me/threads_publish', { creation_id: container.id, access_token: credentials.accessToken }, reqOpts);
      return { remoteId: published.id || container.id || null };
    }
    default:
      throw new Error('投稿サービスが不正です。');
  }
}

export async function postThreadToService(account, posts, options = {}) {
  const results = [];
  let lastRemoteId = null;
  let blueskyRootUri = null;

  for (let i = 0; i < posts.length; i++) {
    const text = posts[i];
    const postOptions = {
      ...options,
      ...(lastRemoteId ? { replyToId: lastRemoteId } : {}),
      ...(blueskyRootUri ? { replyRoot: blueskyRootUri } : {}),
    };
    const res = await postToService(account, text, postOptions);
    results.push(res);
    lastRemoteId = res.remoteId;
    if (account.service === 'bluesky' && i === 0 && res.remoteId) {
      blueskyRootUri = res.remoteId;
    }
  }
  return results;
}

export async function deleteFromService(account, remoteId, options = {}) {
  if (options.dryRun || String(remoteId).startsWith('dry_')) return { simulated: true };
  const credentials = account.credentials;
  const reqOpts = options.requestImpl ? { requestImpl: options.requestImpl } : {};
  switch (account.service) {
    case 'x':
      await fetchJson(`https://api.x.com/2/tweets/${encodeURIComponent(remoteId)}`, { ...reqOpts, method: 'DELETE', headers: { Authorization: `Bearer ${credentials.accessToken}` } });
      return {};
    case 'mastodon': {
      const instanceUrl = normalizeInstanceUrl(account.instanceUrl);
      await fetchJson(`${instanceUrl}/api/v1/statuses/${encodeURIComponent(remoteId)}`, { ...reqOpts, method: 'DELETE', headers: { Authorization: `Bearer ${credentials.accessToken}` } });
      return {};
    }
    case 'misskey': {
      const instanceUrl = normalizeInstanceUrl(account.instanceUrl);
      await fetchJson(`${instanceUrl}/api/notes/delete`, { ...reqOpts, method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ i: credentials.accessToken, noteId: remoteId }) });
      return {};
    }
    case 'bluesky': {
      const [repo, collection, rkey] = String(remoteId).replace(/^at:\/\//, '').split('/');
      if (!repo || !rkey) throw new Error('Bluesky投稿IDを解釈できません。');
      const session = await fetchJson('https://bsky.social/xrpc/com.atproto.server.createSession', { ...reqOpts, method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ identifier: credentials.username, password: credentials.appPassword }) });
      await fetchJson('https://bsky.social/xrpc/com.atproto.repo.deleteRecord', { ...reqOpts, method: 'POST', headers: { Authorization: `Bearer ${session.accessJwt}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ repo, collection: collection || 'app.bsky.feed.post', rkey }) });
      return {};
    }
    case 'threads':
      await fetchJson(`https://graph.threads.com/v1.0/${encodeURIComponent(remoteId)}?access_token=${encodeURIComponent(credentials.accessToken)}`, { ...reqOpts, method: 'DELETE' });
      return {};
    default:
      throw new Error('削除サービスが不正です。');
  }
}
