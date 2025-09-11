import React from 'react';
import ReactDOM from 'react-dom/client';
import { PublicClientApplication } from '@azure/msal-browser';
import App from './App';
import { loadConfig } from './config';

const initializeApp = async () => {
  try {
    const config = await loadConfig();
    
    const msalConfig = {
      auth: {
        clientId: config.spaClientId,
        authority: config.authority,
        redirectUri: config.redirectUri,
      },
      cache: {
        cacheLocation: "sessionStorage",
        storeAuthStateInCookie: false,
      }
    };

    const msalInstance = new PublicClientApplication(msalConfig);

    // Initialize MSAL
    await msalInstance.initialize();

    const root = ReactDOM.createRoot(
      document.getElementById('root') as HTMLElement
    );

    root.render(
      <React.StrictMode>
        <App msalInstance={msalInstance} />
      </React.StrictMode>
    );
  } catch (error) {
    console.error('Failed to initialize application:', error);
    
    // Fallback rendering
    const root = ReactDOM.createRoot(
      document.getElementById('root') as HTMLElement
    );
    
    root.render(
      <div style={{ 
        display: 'flex', 
        justifyContent: 'center', 
        alignItems: 'center', 
        height: '100vh',
        flexDirection: 'column',
        gap: '1rem'
      }}>
        <h1>Configuration Error</h1>
        <p>Failed to load application configuration. Please check the deployment.</p>
        <p style={{ fontSize: '0.9rem', color: '#666' }}>
          Make sure config.local.json exists and contains valid configuration.
        </p>
      </div>
    );
  }
};

initializeApp();
