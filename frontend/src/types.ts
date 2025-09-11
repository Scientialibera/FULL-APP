export interface AppConfig {
  tenantId: string;
  spaClientId: string;
  apiAudience: string;
  apiBaseUrl: string;
  authority: string;
  redirectUri: string;
  simpleUsername?: string;
  simplePassword?: string;
}

export interface Product {
  id?: number;
  name: string;
  description: string;
  price: number;
}

export interface ProductCreate {
  name: string;
  description: string;
  price: number;
}

export interface UserInfo {
  name: string;
  email: string;
  oid: string;
  tid: string;
}
