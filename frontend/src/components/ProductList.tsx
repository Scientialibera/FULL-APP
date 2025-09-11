import React, { useState, useEffect } from 'react';
import { Product, ProductCreate } from '../types';
import { apiService } from '../apiService';

interface ProductListProps {
  isAuthenticated: boolean;
}

export const ProductList: React.FC<ProductListProps> = ({ isAuthenticated }) => {
  const [products, setProducts] = useState<Product[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showForm, setShowForm] = useState(false);
  const [newProduct, setNewProduct] = useState<ProductCreate>({
    name: '',
    description: '',
    price: 0
  });

  const loadProducts = async () => {
    if (!isAuthenticated) return;
    
    setLoading(true);
    setError(null);
    try {
      const data = await apiService.getProducts();
      setProducts(data);
    } catch (err) {
      setError('Failed to load products');
      console.error('Error loading products:', err);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateProduct = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!isAuthenticated) return;

    setLoading(true);
    setError(null);
    try {
      await apiService.createProduct(newProduct);
      setNewProduct({ name: '', description: '', price: 0 });
      setShowForm(false);
      await loadProducts(); // Reload products
    } catch (err) {
      setError('Failed to create product');
      console.error('Error creating product:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProducts();
  }, [isAuthenticated]);

  if (!isAuthenticated) {
    return (
      <div className="card">
        <h2>Products</h2>
        <p>Please sign in to view products.</p>
      </div>
    );
  }

  return (
    <div className="card">
      <div className="card-header">
        <h2>Products</h2>
        <button 
          onClick={() => setShowForm(!showForm)}
          className="btn btn-primary"
        >
          {showForm ? 'Cancel' : 'Add Product'}
        </button>
      </div>

      {error && (
        <div className="error">
          {error}
        </div>
      )}

      {showForm && (
        <form onSubmit={handleCreateProduct} className="product-form">
          <h3>Add New Product</h3>
          <div className="form-group">
            <label htmlFor="name">Name:</label>
            <input
              type="text"
              id="name"
              value={newProduct.name}
              onChange={(e) => setNewProduct(prev => ({ ...prev, name: e.target.value }))}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="description">Description:</label>
            <textarea
              id="description"
              value={newProduct.description}
              onChange={(e) => setNewProduct(prev => ({ ...prev, description: e.target.value }))}
              required
            />
          </div>
          <div className="form-group">
            <label htmlFor="price">Price:</label>
            <input
              type="number"
              id="price"
              step="0.01"
              value={newProduct.price}
              onChange={(e) => setNewProduct(prev => ({ ...prev, price: parseFloat(e.target.value) }))}
              required
            />
          </div>
          <button type="submit" disabled={loading} className="btn btn-success">
            {loading ? 'Creating...' : 'Create Product'}
          </button>
        </form>
      )}

      <div className="products-list">
        {loading && <p>Loading products...</p>}
        {products.length === 0 && !loading && (
          <p>No products found. Add your first product!</p>
        )}
        {products.map((product) => (
          <div key={product.id} className="product-card">
            <h3>{product.name}</h3>
            <p>{product.description}</p>
            <p className="price">${product.price.toFixed(2)}</p>
          </div>
        ))}
      </div>
    </div>
  );
};
