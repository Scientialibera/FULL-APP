import React, { useState, useEffect } from 'react';
import { MsalProvider, AuthenticatedTemplate, UnauthenticatedTemplate, useMsal } from '@azure/msal-react';
import { PublicClientApplication } from '@azure/msal-browser';
import { ProductList } from './components/ProductList';
import { UserProfile } from './components/UserProfile';
import { loadConfig } from './config';
import { apiService } from './apiService';
import { AppConfig } from './types';
import './App.css';

const AppContent: React.FC = () => {
  const { instance, accounts } = useMsal();
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [tokenClaims, setTokenClaims] = useState<any>(null);

  useEffect(() => {
    const initializeApp = async () => {
      try {
        const appConfig = await loadConfig();
        setConfig(appConfig);
        apiService.initialize(appConfig.apiBaseUrl);
      } catch (error) {
        console.error('Failed to initialize app:', error);
      } finally {
        setLoading(false);
      }
    };

    initializeApp();
  }, []);

  useEffect(() => {
    const acquireToken = async () => {
      if (accounts.length > 0 && config) {
        try {
          const response = await instance.acquireTokenSilent({
            scopes: [`${config.apiAudience}/user_impersonation`],
            account: accounts[0]
          });
          
          apiService.setAuthToken(response.accessToken);
          setTokenClaims(response.idTokenClaims);
        } catch (error) {
          console.error('Failed to acquire token:', error);
          try {
            const response = await instance.acquireTokenPopup({
              scopes: [`${config.apiAudience}/user_impersonation`],
              account: accounts[0]
            });
            
            apiService.setAuthToken(response.accessToken);
            setTokenClaims(response.idTokenClaims);
          } catch (popupError) {
            console.error('Failed to acquire token via popup:', popupError);
          }
        }
      }
    };

    acquireToken();
  }, [accounts, config, instance]);

  const handleLogin = async () => {
    if (!config) return;
    
    try {
      await instance.loginPopup({
        scopes: [`${config.apiAudience}/user_impersonation`]
      });
    } catch (error) {
      console.error('Login failed:', error);
    }
  };

  const handleLogout = () => {
    apiService.clearAuthToken();
    instance.logoutPopup();
  };

  if (loading) {
    return <div className="loading">Loading application...</div>;
  }

  if (!config) {
    return <div className="error">Failed to load application configuration</div>;
  }

  return (
    <div className="app">
      <header className="app-header">
        <h1>Azure Fullstack Application</h1>
        <div className="auth-section">
          <AuthenticatedTemplate>
            <span>Welcome, {accounts[0]?.name || 'User'}!</span>
            <button onClick={handleLogout} className="btn btn-outline">
              Sign Out
            </button>
          </AuthenticatedTemplate>
          <UnauthenticatedTemplate>
            <button onClick={handleLogin} className="btn btn-primary">
              Sign In
            </button>
          </UnauthenticatedTemplate>
        </div>
      </header>

      <main className="app-main">
        <AuthenticatedTemplate>
          <div className="content-grid">
            <UserProfile 
              isAuthenticated={accounts.length > 0} 
              tokenClaims={tokenClaims}
            />
            <ProductList isAuthenticated={accounts.length > 0} />
          </div>
        </AuthenticatedTemplate>

        <UnauthenticatedTemplate>
          <div className="welcome-message">
            <h2>Welcome to Azure Fullstack Application</h2>
            <p>
              This application demonstrates modern Azure architecture with:
            </p>
            <ul>
              <li>React SPA with TypeScript</li>
              <li>Python FastAPI backend</li>
              <li>Azure Active Directory authentication</li>
              <li>Azure SQL Database</li>
              <li>Azure Key Vault for secrets</li>
              <li>Azure Cache for Redis</li>
              <li>Container Apps hosting</li>
            </ul>
            <p>Please sign in to start using the application.</p>
          </div>
        </UnauthenticatedTemplate>
      </main>

      <footer className="app-footer">
        <p>
          Powered by Azure • Built with React + FastAPI • 
          <a href="https://github.com/Scientialibera/FULL-APP" target="_blank" rel="noopener noreferrer">
            View Source
          </a>
        </p>
      </footer>
    </div>
  );
};

interface AppProps {
  msalInstance: PublicClientApplication;
}

const App: React.FC<AppProps> = ({ msalInstance }) => {
  return (
    <MsalProvider instance={msalInstance}>
      <AppContent />
    </MsalProvider>
  );
};

export default App;
