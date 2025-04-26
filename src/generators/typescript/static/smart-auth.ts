import { httpClient } from './http-client';

/**
 * SMART on FHIR authentication configuration
 */
export interface SmartAuthConfig {
  /** FHIR server base URL */
  serverUrl: string;
  /** OAuth 2.0 client ID */
  clientId: string;
  /** OAuth 2.0 client secret (optional, for confidential clients) */
  clientSecret?: string;
  /** OAuth 2.0 redirect URI */
  redirectUri: string;
  /** OAuth 2.0 scope (space-separated list) */
  scope: string;
  /** SMART launch context (for EHR launch) */
  launch?: string;
  /** SMART launch/auth endpoint (if not auto-discovered) */
  authorizeUrl?: string;
  /** SMART token endpoint (if not auto-discovered) */
  tokenUrl?: string;
  /** Audience value (if required) */
  aud?: string;
}

/**
 * Token response from OAuth 2.0 server
 */
export interface TokenResponse {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token?: string;
  scope?: string;
  id_token?: string;
  patient?: string;
  encounter?: string;
}

/**
 * SMART on FHIR authentication state
 */
interface SmartAuthState {
  serverUrl: string;
  tokens?: TokenResponse;
  expiresAt?: number;
  config: SmartAuthConfig;
}

/**
 * SMART on FHIR conformance statement
 */
interface CapabilityStatement {
  rest?: Array<{
    security?: {
      extension?: Array<{
        url?: string;
        extension?: Array<{
          url?: string;
          valueUri?: string;
        }>;
      }>;
    };
  }>;
}

/**
 * SMART on FHIR authentication provider
 */
export class SmartAuth {
  private state: SmartAuthState;
  private refreshPromise: Promise<TokenResponse> | null = null;

  /**
   * Creates a new SMART authentication provider
   * @param config Authentication configuration
   */
  constructor(config: SmartAuthConfig) {
    this.state = {
      serverUrl: config.serverUrl,
      config
    };
  }

  /**
   * Authenticates using SMART on FHIR OAuth 2.0
   */
  async authorize(): Promise<TokenResponse> {
    if (this.state.tokens && this.state.expiresAt && this.state.expiresAt > Date.now()) {
      return this.state.tokens;
    }

    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    if (this.state.tokens?.refresh_token) {
      return this.refreshToken();
    }

    // Discover endpoints if not provided
    if (!this.state.config.authorizeUrl || !this.state.config.tokenUrl) {
      await this.discoverAuthEndpoints();
    }

    // Start authorization code flow
    const authUrl = new URL(this.state.config.authorizeUrl!);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('client_id', this.state.config.clientId);
    authUrl.searchParams.set('redirect_uri', this.state.config.redirectUri);
    authUrl.searchParams.set('scope', this.state.config.scope);
    authUrl.searchParams.set('state', this.generateRandomState());
    
    if (this.state.config.aud) {
      authUrl.searchParams.set('aud', this.state.config.aud);
    }
    
    if (this.state.config.launch) {
      authUrl.searchParams.set('launch', this.state.config.launch);
    }

    // Handle the redirect in a browser environment
    if (typeof window !== 'undefined') {
      window.location.href = authUrl.toString();
      return new Promise<TokenResponse>(() => {
        // Never resolves - redirecting
      });
    } else {
      throw new Error('Non-browser SMART authorization not implemented');
    }
  }

  /**
   * Handles the OAuth callback and exchanges the code for tokens
   * @param callbackUrl The callback URL with the authorization code
   */
  async handleCallback(callbackUrl: string): Promise<TokenResponse> {
    const url = new URL(callbackUrl);
    const code = url.searchParams.get('code');
    
    if (!code) {
      const error = url.searchParams.get('error') || 'Missing authorization code';
      throw new Error(`Authorization failed: ${error}`);
    }

    const tokenRequest = new URLSearchParams();
    tokenRequest.set('grant_type', 'authorization_code');
    tokenRequest.set('code', code);
    tokenRequest.set('redirect_uri', this.state.config.redirectUri);
    tokenRequest.set('client_id', this.state.config.clientId);
    
    if (this.state.config.clientSecret) {
      tokenRequest.set('client_secret', this.state.config.clientSecret);
    }

    const response = await httpClient.post(this.state.config.tokenUrl!, {
      body: tokenRequest,
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      }
    });

    const tokens = await response.json<TokenResponse>();
    this.setTokens(tokens);
    return tokens;
  }

  /**
   * Refreshes the access token using a refresh token
   */
  async refreshToken(): Promise<TokenResponse> {
    if (!this.state.tokens?.refresh_token) {
      throw new Error('No refresh token available');
    }

    if (this.refreshPromise) {
      return this.refreshPromise;
    }

    this.refreshPromise = (async () => {
      try {
        const tokenRequest = new URLSearchParams();
        tokenRequest.set('grant_type', 'refresh_token');
        tokenRequest.set('refresh_token', this.state.tokens!.refresh_token!);
        tokenRequest.set('client_id', this.state.config.clientId);
        
        if (this.state.config.clientSecret) {
          tokenRequest.set('client_secret', this.state.config.clientSecret);
        }

        const response = await httpClient.post(this.state.config.tokenUrl!, {
          body: tokenRequest,
          headers: {
            'Content-Type': 'application/x-www-form-urlencoded'
          }
        });

        const tokens = await response.json<TokenResponse>();
        
        // If the server didn't return a refresh token, reuse the current one
        if (!tokens.refresh_token && this.state.tokens?.refresh_token) {
          tokens.refresh_token = this.state.tokens.refresh_token;
        }
        
        this.setTokens(tokens);
        return tokens;
      } catch (error) {
        // Clear tokens if refresh failed
        this.state.tokens = undefined;
        this.state.expiresAt = undefined;
        throw error;
      } finally {
        this.refreshPromise = null;
      }
    })();

    return this.refreshPromise;
  }

  /**
   * Discover auth endpoints from the FHIR server's capability statement
   */
  private async discoverAuthEndpoints(): Promise<void> {
    const url = new URL('metadata', this.state.serverUrl).toString();
    const response = await httpClient(url, {
      headers: {
        'Accept': 'application/fhir+json'
      }
    });

    const capability = await response.json<CapabilityStatement>();
    
    const smartExtension = capability.rest?.[0]?.security?.extension?.find(
      ext => ext.url === 'http://fhir-registry.smarthealthit.org/StructureDefinition/oauth-uris'
    );

    if (!smartExtension?.extension) {
      throw new Error('Server does not support SMART on FHIR authentication');
    }

    const authEndpoint = smartExtension.extension.find(
      ext => ext.url === 'authorize'
    )?.valueUri;

    const tokenEndpoint = smartExtension.extension.find(
      ext => ext.url === 'token'
    )?.valueUri;

    if (!authEndpoint || !tokenEndpoint) {
      throw new Error('Server does not provide required OAuth 2.0 endpoints');
    }

    this.state.config.authorizeUrl = authEndpoint;
    this.state.config.tokenUrl = tokenEndpoint;
  }

  /**
   * Updates current tokens and calculates expiration time
   */
  private setTokens(tokens: TokenResponse): void {
    this.state.tokens = tokens;
    this.state.expiresAt = Date.now() + (tokens.expires_in * 1000);
  }

  /**
   * Gets current access token, refreshing if needed
   */
  async getAccessToken(): Promise<string> {
    const tokens = await this.authorize();
    return tokens.access_token;
  }

  /**
   * Generates a random state parameter for OAuth
   */
  private generateRandomState(): string {
    return Math.random().toString(36).substring(2, 15);
  }

  /**
   * Creates a hook that adds SMART authorization headers to requests
   */
  createAuthorizationHook() {
    return async (request: Request) => {
      // Skip auth for token endpoint and discovery endpoint
      const url = new URL(request.url);
      const isAuthEndpoint = 
        this.state.config.tokenUrl?.includes(url.pathname) || 
        url.pathname.endsWith('/metadata');
      
      if (isAuthEndpoint) {
        return request;
      }

      try {
        const token = await this.getAccessToken();
        const headers = new Headers(request.headers);
        headers.set('Authorization', `Bearer ${token}`);
        
        return new Request(request, { headers });
      } catch (error) {
        console.error('Failed to get access token for request', error);
        return request;
      }
    };
  }
} 