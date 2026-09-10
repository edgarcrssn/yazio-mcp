import { Yazio, YazioAuth } from "yazio";
import { readFileSync, writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

export interface Token {
  token_type: string;
  access_token: string;
  refresh_token: string;
  expires_in: number;
  expires_at: number;
}

const PROJECT_ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const TOKEN_PATH = join(PROJECT_ROOT, ".yazio-token.json");


function loadCachedToken(): Token | null {
  try {
    const data = JSON.parse(readFileSync(TOKEN_PATH, "utf-8"));
    if (data.expires_at && Date.now() < data.expires_at - 60_000) {
      return data;
    }
  } catch {}
  return null;
}

function saveCachedToken(token: Token): void {
  writeFileSync(TOKEN_PATH, JSON.stringify(token, null, 2));
}

let clientInstance: Yazio | null = null;

export function getClient(): Yazio {
  if (clientInstance) return clientInstance;

  const cached = loadCachedToken();
  const username = process.env.YAZIO_USERNAME;
  const password = process.env.YAZIO_PASSWORD;
  const accessToken = process.env.YAZIO_ACCESS_TOKEN;
  const refreshToken = process.env.YAZIO_REFRESH_TOKEN;

  // Mode 1: Token direct (pour les comptes Sign in with Apple)
  if (accessToken) {
    const token: Token = cached ?? {
      token_type: "Bearer",
      access_token: accessToken,
      refresh_token: refreshToken ?? "",
      expires_in: 3600,
      expires_at: Date.now() + 3600_000,
    };

    clientInstance = new Yazio({
      token,
      onRefresh: ({ token }: { token: Token }) => saveCachedToken(token),
    });
    return clientInstance;
  }

  // Mode 2: Credentials classiques (email + password)
  if (!username || !password) {
    throw new Error(
      "Set either YAZIO_ACCESS_TOKEN (for Apple Sign-In accounts) or both YAZIO_USERNAME and YAZIO_PASSWORD"
    );
  }

  if (cached) {
    clientInstance = new Yazio({
      token: cached,
      credentials: { username, password },
      onRefresh: ({ token }: { token: Token }) => saveCachedToken(token),
    });
  } else {
    clientInstance = new Yazio({
      credentials: { username, password },
      onRefresh: ({ token }: { token: Token }) => saveCachedToken(token),
    });
  }

  return clientInstance;
}

let authInstance: YazioAuth | null = null;

export async function getYazioToken(): Promise<Token> {
  if (!authInstance) {
    const cached = loadCachedToken();
    const username = process.env.YAZIO_USERNAME;
    const password = process.env.YAZIO_PASSWORD;
    const accessToken = process.env.YAZIO_ACCESS_TOKEN;
    const refreshToken = process.env.YAZIO_REFRESH_TOKEN;

    if (accessToken) {
      const token: Token = cached ?? {
        token_type: "Bearer",
        access_token: accessToken,
        refresh_token: refreshToken ?? "",
        expires_in: 3600,
        expires_at: Date.now() + 3600_000,
      };
      authInstance = new YazioAuth({
        token,
        onRefresh: ({ token }: { token: Token }) => saveCachedToken(token),
      });
    } else if (username && password) {
      if (cached) {
        authInstance = new YazioAuth({
          token: cached,
          credentials: { username, password },
          onRefresh: ({ token }: { token: Token }) => saveCachedToken(token),
        });
      } else {
        authInstance = new YazioAuth({
          credentials: { username, password },
          onRefresh: ({ token }: { token: Token }) => saveCachedToken(token),
        });
      }
    } else {
      throw new Error(
        "Set either YAZIO_ACCESS_TOKEN or both YAZIO_USERNAME and YAZIO_PASSWORD"
      );
    }
  }
  return authInstance.authenticate();
}

export function todayISO(): string {
  return new Date().toISOString().slice(0, 10);
}
