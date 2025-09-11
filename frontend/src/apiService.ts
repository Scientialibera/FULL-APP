import axios, { AxiosInstance } from 'axios';
import { Product, ProductCreate, UserInfo } from './types';

class ApiService {
  private axiosInstance: AxiosInstance;

  constructor() {
    this.axiosInstance = axios.create();
  }

  public initialize(apiBaseUrl: string) {
    this.axiosInstance = axios.create({
      baseURL: apiBaseUrl,
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  public setAuthToken(token: string) {
    this.axiosInstance.defaults.headers.common['Authorization'] = `Bearer ${token}`;
  }

  public clearAuthToken() {
    delete this.axiosInstance.defaults.headers.common['Authorization'];
  }

  public async getProducts(): Promise<Product[]> {
    const response = await this.axiosInstance.get<Product[]>('/api/products');
    return response.data;
  }

  public async createProduct(product: ProductCreate): Promise<Product> {
    const response = await this.axiosInstance.post<Product>('/api/products', product);
    return response.data;
  }

  public async getUserInfo(): Promise<UserInfo> {
    const response = await this.axiosInstance.get<UserInfo>('/api/user');
    return response.data;
  }

  public async checkHealth(): Promise<any> {
    const response = await this.axiosInstance.get('/healthz');
    return response.data;
  }
}

export const apiService = new ApiService();
