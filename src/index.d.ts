/// <reference types="node" />

import type { LookupAddress } from 'node:dns';
import type { URL } from 'node:url';

export type SupportedService = 'x' | 'mastodon' | 'bluesky' | 'misskey' | 'threads';

export declare const SUPPORTED_SERVICES: ReadonlySet<SupportedService>;

export declare const SERVICE_LABELS: Record<SupportedService, string>;

export interface XCredentials {
  accessToken: string;
}

export interface MastodonCredentials {
  accessToken: string;
}

export interface MisskeyCredentials {
  accessToken: string;
}

export interface BlueskyCredentials {
  username: string;
  appPassword: string;
}

export interface ThreadsCredentials {
  accessToken: string;
}

export type ServiceCredentials =
  | XCredentials
  | MastodonCredentials
  | MisskeyCredentials
  | BlueskyCredentials
  | ThreadsCredentials;

export interface CrossPosterAccount {
  service: SupportedService;
  instanceUrl?: string | null;
  credentials: Record<string, any>;
}

export interface PostOptions {
  dryRun?: boolean;
  requestImpl?: (
    url: string,
    options: {
      method?: string;
      headers?: Record<string, string>;
      body?: string | URLSearchParams;
      signal?: AbortSignal;
    }
  ) => Promise<{
    status: number;
    ok: boolean;
    text: () => Promise<string>;
  }>;
}

export interface PostResult {
  remoteId: string | null;
  simulated?: boolean;
}

export interface DeleteResult {
  simulated?: boolean;
}

export declare function normalizeInstanceUrl(value: unknown): string;

export declare function isUnsafeIpv4(address: string): boolean;

export declare function parseIpv6(address: string): number[] | null;

export declare function isUnsafeAddress(address: string): boolean;

export declare function createPinnedAddressLookup(
  address: string
): (
  hostname: string,
  options: { all?: boolean },
  callback: (err: Error | null, addressOrList: string | LookupAddress[], family?: number) => void
) => void;

export declare function resolveSafeExternalUrl(
  rawUrl: string | URL
): Promise<{ parsed: URL; address: string }>;

export declare function assertSafeExternalUrl(rawUrl: string | URL): Promise<URL>;

export declare function encryptCredentials(value: unknown, key: Buffer): string;

export declare function decryptCredentials<T = unknown>(value: string, key: Buffer): T;

export declare function requestExternal(
  rawUrl: string | URL,
  options?: {
    method?: string;
    headers?: Record<string, string>;
    body?: string | URLSearchParams | Buffer;
    signal?: AbortSignal;
  }
): Promise<{
  status: number;
  ok: boolean;
  text: () => Promise<string>;
}>;

export declare function postToService(
  account: CrossPosterAccount,
  text: string,
  options?: PostOptions
): Promise<PostResult>;

export declare function deleteFromService(
  account: CrossPosterAccount,
  remoteId: string,
  options?: PostOptions
): Promise<DeleteResult>;
