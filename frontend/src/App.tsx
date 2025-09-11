import React, { useState, useEffect } from 'react';
import { MsalProvider, useMsal } from '@azure/msal-react';
import { PublicClientApplication } from '@azure/msal-browser';
import { ProductList } from './components/ProductList';
import { UserProfile } from './components/UserProfile';
import { SimpleLogin } from './components/SimpleLogin';
import { loadConfig } from './config';
import { apiService } from './apiService';
import { simpleAuthService, SimpleAuthUser } from './simpleAuth';
import { AppConfig } from './types';
import './App.css';

const AppContent: React.FC = () => {
  const { instance, accounts } = useMsal();
  const [config, setConfig] = useState<AppConfig | null>(null);
  const [loading, setLoading] = useState(true);
  const [tokenClaims, setTokenClaims] = useState<any>(null);
  const [simpleUser, setSimpleUser] = useState<SimpleAuthUser | null>(null);
  const [simpleLoginLoading, setSimpleLoginLoading] = useState(false);
  const [simpleLoginError, setSimpleLoginError] = useState<string | null>(null);
  const [authMode, setAuthMode] = useState<'azure' | 'simple'>('azure');

  useEffect(() => {
    const initializeApp = async () => {
      try {
        const appConfig = await loadConfig();
        setConfig(appConfig);
        apiService.initialize(appConfig.apiBaseUrl);
        
        // Check if user is already logged in with simple auth
        const existingUser = simpleAuthService.getCurrentUser();
        if (existingUser) {
          setSimpleUser(existingUser);
          setAuthMode('simple');
        }
        // Note: Azure AD login state is handled by MSAL automatically
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
    if (authMode === 'simple') {
      simpleAuthService.logout();
      setSimpleUser(null);
      setAuthMode('azure');
    } else {
      apiService.clearAuthToken();
      instance.logoutPopup();
    }
  };

  const handleSimpleLogin = async (username: string, password: string) => {
    setSimpleLoginLoading(true);
    setSimpleLoginError(null);
    
    try {
      const user = await simpleAuthService.login(username, password);
      setSimpleUser(user);
      setAuthMode('simple');
    } catch (error) {
      setSimpleLoginError(error instanceof Error ? error.message : 'Login failed');
    } finally {
      setSimpleLoginLoading(false);
    }
  };

  const switchToSimpleAuth = () => {
    setAuthMode('simple');
  };

  const switchToAzureAuth = () => {
    setAuthMode('azure');
  };

  if (loading) {
    return <div className="loading">Loading application...</div>;
  }

  if (!config) {
    return <div className="error">Failed to load application configuration</div>;
  }

  const isAuthenticated = authMode === 'simple' ? simpleUser !== null : accounts.length > 0;
  const currentUserName = authMode === 'simple' 
    ? simpleUser?.name || 'Simple User'
    : accounts[0]?.name || 'User';

  return (
    <div className="app">
      <header className="app-header">
        <h1>Azure Fullstack Application</h1>
        <div className="auth-section">
          {isAuthenticated ? (
            <div className="authenticated-header">
              <span>Welcome, {currentUserName}! ({authMode === 'simple' ? 'Simple Auth' : 'Azure AD'})</span>
              <button onClick={handleLogout} className="btn btn-outline">
                Sign Out
              </button>
            </div>
          ) : (
            <div className="unauthenticated-header">
              {authMode === 'azure' ? (
                <div className="auth-options">
                  <button onClick={handleLogin} className="btn btn-primary">
                    Sign In with Microsoft
                  </button>
                  <button onClick={switchToSimpleAuth} className="btn btn-secondary">
                    Use Simple Login
                  </button>
                </div>
              ) : (
                <div className="auth-options">
                  <button onClick={switchToAzureAuth} className="btn btn-secondary">
                    Back to Microsoft Login
                  </button>
                </div>
              )}
            </div>
          )}
        </div>
      </header>

      <main className="app-main">
        {isAuthenticated ? (
          <div className="content-grid">
            <UserProfile 
              isAuthenticated={true} 
              tokenClaims={authMode === 'simple' ? { name: simpleUser?.name, preferred_username: simpleUser?.email } : tokenClaims}
            />
            <ProductList isAuthenticated={true} />
          </div>
        ) : (
          <div className="welcome-container">
            {authMode === 'simple' ? (
              <SimpleLogin 
                onLogin={handleSimpleLogin}
                loading={simpleLoginLoading}
                error={simpleLoginError}
              />
            ) : (
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
                <p>Please choose your preferred sign-in method.</p>
              </div>
            )}
          </div>
        )}
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
