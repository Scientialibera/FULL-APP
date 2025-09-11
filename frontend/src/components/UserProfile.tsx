import React, { useState, useEffect } from 'react';
import { UserInfo } from '../types';
import { apiService } from '../apiService';

interface UserProfileProps {
  isAuthenticated: boolean;
  tokenClaims?: any;
}

export const UserProfile: React.FC<UserProfileProps> = ({ isAuthenticated, tokenClaims }) => {
  const [userInfo, setUserInfo] = useState<UserInfo | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const loadUserInfo = async () => {
    if (!isAuthenticated) return;
    
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getUserInfo();
      setUserInfo(data);
    } catch (err) {
      setError('Failed to load user info');
      console.error('Error loading user info:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadUserInfo();
  }, [isAuthenticated]);

  if (!isAuthenticated) {
    return null;
  }

  return (
    <div className="card">
      <h2>User Profile</h2>
      
      {error && (
        <div className="error">
          {error}
        </div>
      )}

      {loading && <p>Loading user info...</p>}

      {userInfo && (
        <div className="user-info">
          <p><strong>Name:</strong> {userInfo.name}</p>
          <p><strong>Email:</strong> {userInfo.email}</p>
          <p><strong>User ID:</strong> {userInfo.oid}</p>
          <p><strong>Tenant ID:</strong> {userInfo.tid}</p>
        </div>
      )}

      {tokenClaims && (
        <div className="token-claims">
          <h3>Token Claims</h3>
          <pre>{JSON.stringify(tokenClaims, null, 2)}</pre>
        </div>
      )}
    </div>
  );
};
