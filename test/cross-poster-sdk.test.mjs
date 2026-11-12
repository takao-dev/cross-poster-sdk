import assert from 'node:assert/strict';
import https from 'node:https';
import { EventEmitter } from 'node:events';
import { randomBytes } from 'node:crypto';
import test from 'node:test';
import {
  assertSafeExternalUrl,
  createPinnedAddressLookup,
  decryptCredentials,
  deleteFromService,
  encryptCredentials,
  isUnsafeAddress,
  normalizeInstanceUrl,
  postToService,
  postThreadToService,
  countServiceCharacters,
  splitPostIntoThreads,
  requestExternal,
  SUPPORTED_SERVICES,
  SERVICE_LABELS,
  SERVICE_LIMITS,
} from '../src/index.mjs';

test('exposes supported services and display labels', () => {
  assert.equal(SUPPORTED_SERVICES.size, 5);
  assert.ok(SUPPORTED_SERVICES.has('x'));
  assert.ok(SUPPORTED_SERVICES.has('mastodon'));
  assert.ok(SUPPORTED_SERVICES.has('bluesky'));
  assert.ok(SUPPORTED_SERVICES.has('misskey'));
  assert.ok(SUPPORTED_SERVICES.has('threads'));
  assert.equal(SERVICE_LABELS.bluesky, 'Bluesky');
});

test('blocks private, loopback, link-local, documentation, and IPv4-mapped IPv6 addresses (SSRF guard)', async () => {
  assert.equal(isUnsafeAddress('127.0.0.1'), true);
  assert.equal(isUnsafeAddress('10.0.0.1'), true);
  assert.equal(isUnsafeAddress('169.254.169.254'), true);
  assert.equal(isUnsafeAddress('192.168.1.1'), true);
  assert.equal(isUnsafeAddress('::1'), true);
  assert.equal(isUnsafeAddress('::ffff:127.0.0.1'), true);
  assert.equal(isUnsafeAddress('fe80::1'), true);
  assert.equal(isUnsafeAddress('2001:db8::1'), true);
  assert.equal(isUnsafeAddress('93.184.216.34'), false);
  assert.equal(isUnsafeAddress('2606:2800:220:1:248:1893:25c8:1946'), false);

  await assert.rejects(() => assertSafeExternalUrl('http://example.com'), /HTTPS/);
  await assert.rejects(() => assertSafeExternalUrl('https://127.0.0.1/api'), /内部ネットワーク/);
  await assert.rejects(() => assertSafeExternalUrl('https://metadata.google.internal'), /内部ネットワーク/);
  await assert.rejects(() => assertSafeExternalUrl('https://user:pass@example.com'), /認証情報/);
});

test('validates and normalizes instance URLs', () => {
  assert.equal(normalizeInstanceUrl(''), '');
  assert.equal(normalizeInstanceUrl('https://mastodon.social/explore'), 'https://mastodon.social');
  assert.equal(normalizeInstanceUrl('https://misskey.io/'), 'https://misskey.io');
  assert.throws(() => normalizeInstanceUrl('http://insecure.social'), /HTTPS/);
  assert.throws(() => normalizeInstanceUrl('https://user:pass@insecure.social'), /認証情報/);
  assert.throws(() => normalizeInstanceUrl('not-a-url'), /HTTPS/);
});

test('pins resolved IP address to prevent DNS rebinding', () => {
  const lookup = createPinnedAddressLookup('93.184.216.34');
  lookup('mastodon.social', { all: true }, (err, list) => {
    assert.equal(err, null);
    assert.deepEqual(list, [{ address: '93.184.216.34', family: 4 }]);
  });

  lookup('mastodon.social', {}, (err, address, family) => {
    assert.equal(err, null);
    assert.equal(address, '93.184.216.34');
    assert.equal(family, 4);
  });
});

test('encrypts and decrypts account credentials with AES-256-GCM v1 envelope', () => {
  const key = randomBytes(32);
  const envelope = encryptCredentials({ accessToken: 'secret-token' }, key);
  assert.match(envelope, /^v1\./);
  assert.deepEqual(decryptCredentials(envelope, key), { accessToken: 'secret-token' });

  // Tampering detection
  assert.throws(() => decryptCredentials('v2.invalid.envelope.format', key), /暗号化データが不正/);
  const tampered = envelope.slice(0, -4) + 'AAAA';
  assert.throws(() => decryptCredentials(tampered, key));
});

test('supports unified posting and deletion across X, Mastodon, Misskey, Bluesky, and Threads', async () => {
  const calls = [];
  const mockRequest = async (url, options) => {
    calls.push({ url, method: options.method });
    if (url.includes('createSession')) {
      return { ok: true, status: 200, text: async () => JSON.stringify({ did: 'did:plc:123', accessJwt: 'jwt' }) };
    }
    return {
      ok: true,
      status: 200,
      text: async () =>
        JSON.stringify({
          data: { id: 'x_1' },
          id: 'm_1',
          createdNote: { id: 'mk_1' },
          uri: 'at://did:plc:123/app.bsky.feed.post/rkey1',
        }),
    };
  };

  assert.equal((await postToService({ service: 'x', credentials: { accessToken: 't' } }, 'hello', { requestImpl: mockRequest })).remoteId, 'x_1');
  assert.equal((await postToService({ service: 'mastodon', instanceUrl: 'https://mastodon.social', credentials: { accessToken: 't' } }, 'hello', { requestImpl: mockRequest })).remoteId, 'm_1');
  assert.equal((await postToService({ service: 'misskey', instanceUrl: 'https://misskey.io', credentials: { accessToken: 't' } }, 'hello', { requestImpl: mockRequest })).remoteId, 'mk_1');
  assert.equal((await postToService({ service: 'bluesky', credentials: { username: 'u', appPassword: 'p' } }, 'hello', { requestImpl: mockRequest })).remoteId, 'at://did:plc:123/app.bsky.feed.post/rkey1');
  assert.equal((await postToService({ service: 'threads', credentials: { accessToken: 't' } }, 'hello', { requestImpl: mockRequest })).remoteId, 'm_1');

  // Deletions
  await deleteFromService({ service: 'x', credentials: { accessToken: 't' } }, 'x_1', { requestImpl: mockRequest });
  await deleteFromService({ service: 'mastodon', instanceUrl: 'https://mastodon.social', credentials: { accessToken: 't' } }, 'm_1', { requestImpl: mockRequest });
  await deleteFromService({ service: 'misskey', instanceUrl: 'https://misskey.io', credentials: { accessToken: 't' } }, 'mk_1', { requestImpl: mockRequest });
  await deleteFromService({ service: 'bluesky', credentials: { username: 'u', appPassword: 'p' } }, 'at://did:plc:123/app.bsky.feed.post/rkey1', { requestImpl: mockRequest });
  await deleteFromService({ service: 'threads', credentials: { accessToken: 't' } }, 'th_1', { requestImpl: mockRequest });
  assert.ok(calls.length >= 10);
});

test('handles dryRun simulation mode without network calls', async () => {
  const result = await postToService({ service: 'x', credentials: {} }, 'test message', { dryRun: true });
  assert.ok(result.remoteId?.startsWith('dry_x_'));
  assert.equal(result.simulated, true);

  const del = await deleteFromService({ service: 'x', credentials: {} }, result.remoteId, { dryRun: false });
  assert.equal(del.simulated, true);
});

test('throws on unsupported service names', async () => {
  await assert.rejects(
    () => postToService({ service: 'unsupported', credentials: {} }, 'test'),
    /投稿サービスが不正/
  );
  await assert.rejects(
    () => deleteFromService({ service: 'unsupported', credentials: {} }, 'id123'),
    /削除サービスが不正/
  );
});

test('countServiceCharacters accurately measures service-specific character weights', () => {
  // X: ASCII is 1, CJK is 2, URL is 23
  assert.equal(countServiceCharacters('x', 'hello'), 5);
  assert.equal(countServiceCharacters('x', 'こんにちは'), 10);
  assert.equal(countServiceCharacters('x', 'Visit https://example.com/test today!'), 6 + 23 + 7);

  // Bluesky: 300 grapheme clusters
  assert.equal(countServiceCharacters('bluesky', 'Hello 🚀'), 7);

  // Mastodon: code points
  assert.equal(countServiceCharacters('mastodon', 'Fediverse 🎉'), 11);
  assert.equal(SERVICE_LIMITS.mastodon, 500);
});

test('splitPostIntoThreads divides long posts with numbering indicators', () => {
  const shortText = 'Short announcement';
  assert.deepEqual(splitPostIntoThreads('bluesky', shortText), [shortText]);

  const longText = 'First paragraph describing a major product announcement with lots of interesting details, technical architecture notes, and security disclosures.\n\nSecond paragraph following up with release dates, step-by-step instructions, migration guides, and community forum links.\n\nThird paragraph concluding with deep thank-you remarks to everyone involved across all engineering and design teams.';
  const threads = splitPostIntoThreads('x', longText);
  assert.ok(threads.length >= 2);
  assert.ok(threads[0].endsWith(`(1/${threads.length})`));
  assert.ok(threads[threads.length - 1].endsWith(`(${threads.length}/${threads.length})`));

  for (const chunk of threads) {
    assert.ok(countServiceCharacters('x', chunk) <= SERVICE_LIMITS.x);
  }
});

test('postThreadToService threads multiple sequential replies', async () => {
  const postedBodies = [];
  const mockRequest = async (url, options) => {
    postedBodies.push(JSON.parse(options.body));
    return {
      ok: true,
      status: 200,
      text: async () => JSON.stringify({ data: { id: `tweet_${postedBodies.length}` } }),
    };
  };

  const account = { service: 'x', credentials: { accessToken: 'token' } };
  const thread = ['Post 1', 'Post 2', 'Post 3'];
  const results = await postThreadToService(account, thread, { requestImpl: mockRequest });

  assert.equal(results.length, 3);
  assert.equal(results[0].remoteId, 'tweet_1');
  assert.equal(results[1].remoteId, 'tweet_2');
  assert.equal(results[2].remoteId, 'tweet_3');

  // Verify first post has no reply, but subsequent posts link to previous
  assert.equal(postedBodies[0].reply, undefined);
  assert.deepEqual(postedBodies[1].reply, { in_reply_to_tweet_id: 'tweet_1' });
  assert.deepEqual(postedBodies[2].reply, { in_reply_to_tweet_id: 'tweet_2' });
});

test('postThreadToService handles Bluesky, Mastodon, Misskey, and Threads threading', async () => {
  // Bluesky
  const bskyBodies = [];
  const bskyMock = async (url, options) => {
    if (url.includes('createSession')) {
      return { ok: true, status: 200, text: async () => JSON.stringify({ did: 'did:plc:test', accessJwt: 'jwt' }) };
    }
    const b = JSON.parse(options.body);
    bskyBodies.push(b);
    return { ok: true, status: 200, text: async () => JSON.stringify({ uri: `at://did:plc:test/post_${bskyBodies.length}` }) };
  };
  const bskyAccount = { service: 'bluesky', credentials: { username: 'u', appPassword: 'p' } };
  const bskyRes = await postThreadToService(bskyAccount, ['B1', 'B2'], { requestImpl: bskyMock });
  assert.equal(bskyRes.length, 2);
  assert.equal(bskyBodies[0].record.reply, undefined);
  assert.ok(bskyBodies[1].record.reply);
  assert.equal(bskyBodies[1].record.reply.root.uri, 'at://did:plc:test/post_1');
  assert.equal(bskyBodies[1].record.reply.parent.uri, 'at://did:plc:test/post_1');

  // Mastodon
  const mastoForms = [];
  const mastoMock = async (url, options) => {
    mastoForms.push(options.body.toString());
    return { ok: true, status: 200, text: async () => JSON.stringify({ id: `m_${mastoForms.length}` }) };
  };
  const mastoAccount = { service: 'mastodon', instanceUrl: 'https://mastodon.social', credentials: { accessToken: 't' } };
  const mastoRes = await postThreadToService(mastoAccount, ['M1', 'M2'], { requestImpl: mastoMock });
  assert.equal(mastoRes.length, 2);
  assert.ok(!mastoForms[0].includes('in_reply_to_id'));
  assert.ok(mastoForms[1].includes('in_reply_to_id=m_1'));

  // Misskey
  const misskeyBodies = [];
  const misskeyMock = async (url, options) => {
    misskeyBodies.push(JSON.parse(options.body));
    return { ok: true, status: 200, text: async () => JSON.stringify({ createdNote: { id: `mk_${misskeyBodies.length}` } }) };
  };
  const misskeyAccount = { service: 'misskey', instanceUrl: 'https://misskey.io', credentials: { accessToken: 't' } };
  const misskeyRes = await postThreadToService(misskeyAccount, ['MK1', 'MK2'], { requestImpl: misskeyMock });
  assert.equal(misskeyRes.length, 2);
  assert.equal(misskeyBodies[0].replyId, undefined);
  assert.equal(misskeyBodies[1].replyId, 'mk_1');

  // Threads
  const threadsForms = [];
  const threadsMock = async (url, options) => {
    threadsForms.push(options.body ? options.body.toString() : '');
    return { ok: true, status: 200, text: async () => JSON.stringify({ id: `th_${threadsForms.length}` }) };
  };
  const threadsAccount = { service: 'threads', credentials: { accessToken: 't' } };
  const threadsRes = await postThreadToService(threadsAccount, ['TH1', 'TH2'], { requestImpl: threadsMock });
  assert.equal(threadsRes.length, 2);
  assert.ok(threadsForms.some(f => f.includes('reply_to_id=')));
});

test('splitPostIntoThreads edge cases and slicing', () => {
  // Empty
  assert.deepEqual(splitPostIntoThreads('bluesky', ''), []);
  assert.deepEqual(splitPostIntoThreads('bluesky', '   '), []);

  // numbering: false
  const unnumbered = splitPostIntoThreads('x', 'A'.repeat(200) + '\n\n' + 'B'.repeat(200), { numbering: false });
  assert.equal(unnumbered.length, 2);
  assert.ok(!unnumbered[0].includes('(1/'));

  // Sentence split and deep slice of a long single word
  const longSentence = 'Short start. ' + '極'.repeat(300) + ' End.';
  const chunks = splitPostIntoThreads('x', longSentence);
  assert.ok(chunks.length > 1);
  for (const c of chunks) {
    assert.ok(countServiceCharacters('x', c) <= SERVICE_LIMITS.x);
  }

  // Paragraph with multiple sentences where second sentence fits into next sub chunk
  const multiSentencePara = 'A'.repeat(200) + '. ' + 'B'.repeat(100) + '.';
  const splitSentences = splitPostIntoThreads('x', multiSentencePara);
  assert.equal(splitSentences.length, 2);
});

test('countServiceCharacters fallbacks when Intl.Segmenter is absent', () => {
  const originalSegmenter = Intl.Segmenter;
  try {
    delete Intl.Segmenter;
    assert.equal(countServiceCharacters('bluesky', 'Hello World 🚀'), 13);
  } finally {
    Intl.Segmenter = originalSegmenter;
  }
});

test('resolveSafeExternalUrl and assertSafeExternalUrl error handling', async () => {
  // Valid URL passes assertSafeExternalUrl
  const parsed = await assertSafeExternalUrl('https://mastodon.social/api/v1');
  assert.equal(parsed.hostname, 'mastodon.social');

  // Invalid URL format
  await assert.rejects(() => assertSafeExternalUrl('not a valid url'), /外部URLが不正/);

  // Unresolvable domain
  await assert.rejects(() => assertSafeExternalUrl('https://non-existent-domain-xyz-404-safe.org'), /ホストを解決できません/);
});

test('fetchJson handles API error messages and non-JSON error payloads', async () => {
  const mockErrApi = async () => ({
    ok: false,
    status: 400,
    text: async () => JSON.stringify({ error: { message: 'Bad request message' } }),
  });
  await assert.rejects(
    () => postToService({ service: 'x', credentials: { accessToken: 't' } }, 'test', { requestImpl: mockErrApi }),
    /Bad request message/
  );

  const mockHtmlErr = async () => ({
    ok: false,
    status: 502,
    text: async () => '<html>502 Bad Gateway</html>',
  });
  await assert.rejects(
    () => postToService({ service: 'x', credentials: { accessToken: 't' } }, 'test', { requestImpl: mockHtmlErr }),
    /外部APIエラー \(502\)/
  );
});

test('requestExternal performs safe HTTPS requests with size limit guard', async () => {
  const originalRequest = https.request;
  try {
    // 1. Successful request
    https.request = (options, cb) => {
      const req = new EventEmitter();
      req.write = () => {};
      req.end = () => {
        const res = new EventEmitter();
        res.statusCode = 200;
        cb(res);
        res.emit('data', Buffer.from('{"status":"ok"}'));
        res.emit('end');
      };
      return req;
    };

    const res = await requestExternal('https://mastodon.social/test', {
      method: 'POST',
      body: 'payload',
    });
    assert.equal(res.ok, true);
    assert.equal(res.status, 200);
    assert.equal(await res.text(), '{"status":"ok"}');

    // 2. Request exceeding 2MB is destroyed
    https.request = (options, cb) => {
      const req = new EventEmitter();
      req.destroy = (err) => {
        req.emit('error', err);
      };
      req.write = () => {};
      req.end = () => {
        const res = new EventEmitter();
        res.statusCode = 200;
        cb(res);
        res.emit('data', Buffer.alloc(2 * 1024 * 1024 + 100));
      };
      return req;
    };

    await assert.rejects(
      () => requestExternal('https://mastodon.social/oversized'),
      /外部APIレスポンスが大きすぎます/
    );
  } finally {
    https.request = originalRequest;
  }
});
