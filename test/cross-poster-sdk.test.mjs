import assert from 'node:assert/strict';
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
  SUPPORTED_SERVICES,
  SERVICE_LABELS,
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
