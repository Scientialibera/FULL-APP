import { apiService } from './apiService';

export interface SimpleAuthUser {
  username: string;
  name: string;
  email: string;
}

class SimpleAuthService {
  private currentUser: SimpleAuthUser | null = null;

  public async login(username: string, password: string): Promise<SimpleAuthUser> {
    try {
      // Validate credentials locally - no backend call needed
      if (username === 'demo' && password === 'demo123') {
        // Create user object for demo user
        this.currentUser = {
          username: 'demo',
          name: 'Demo User',
          email: 'demo@example.com'
        };

        // For demo purposes, we'll use a placeholder token
        // In a real scenario, you'd get a proper Azure AD token here
        const demoToken = 'demo-token-' + Date.now();
        
        // Store in sessionStorage for persistence
        sessionStorage.setItem('simpleAuthUser', JSON.stringify(this.currentUser));
        sessionStorage.setItem('simpleAuthToken', demoToken);

        // Set token for API calls - but backend will handle real auth
        apiService.setAuthToken(demoToken);

        return this.currentUser;
      } else {
        throw new Error('Invalid username or password');
      }
    } catch (error) {
      console.error('Login failed:', error);
      throw error;
    }
  }

  public logout(): void {
    this.currentUser = null;
    apiService.clearAuthToken();
    
    // Clear from sessionStorage
    sessionStorage.removeItem('simpleAuthUser');
    sessionStorage.removeItem('simpleAuthToken');
  }

  public getCurrentUser(): SimpleAuthUser | null {
    if (this.currentUser) {
      return this.currentUser;
    }

    // Try to restore from sessionStorage
    const storedUser = sessionStorage.getItem('simpleAuthUser');
    const storedToken = sessionStorage.getItem('simpleAuthToken');
    
    if (storedUser && storedToken) {
      this.currentUser = JSON.parse(storedUser);
      apiService.setAuthToken(storedToken);
      return this.currentUser;
    }

    return null;
  }

  public isAuthenticated(): boolean {
    return this.getCurrentUser() !== null;
  }
}

export const simpleAuthService = new SimpleAuthService();
