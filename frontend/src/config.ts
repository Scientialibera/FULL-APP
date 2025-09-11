import { AppConfig } from './types';

export const loadConfig = async (): Promise<AppConfig> => {
  try {
    const response = await fetch('/config.local.json');
    if (!response.ok) {
      throw new Error('Failed to load configuration');
    }
    return await response.json();
  } catch (error) {
    console.error('Failed to load app configuration:', error);
    // Fallback configuration for development
    return {
      tenantId: 'your-tenant-id',
      spaClientId: 'your-spa-client-id',
      apiAudience: 'api://your-api-client-id',
      apiBaseUrl: 'https://your-api-url',
      authority: 'https://login.microsoftonline.com/your-tenant-id',
      redirectUri: window.location.origin
    };
  }
};
