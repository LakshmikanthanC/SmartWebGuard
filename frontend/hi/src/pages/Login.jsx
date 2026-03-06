import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";
import { useTheme } from "../context/ThemeContext";
import "./Login.css";

export default function Login() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const { isDarkMode } = useTheme();
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError("");
    setIsLoading(true);

    try {
      await login(email, password);
      // Redirect to URL Scanner page after successful login
      navigate("/");
    } catch (err) {
      setError(err.message || "Login failed. Please try again.");
    } finally {
      setIsLoading(false);
    }
  };

  return (
    <div className={`login-page ${isDarkMode ? "dark" : "light"}`}>
      <div className="login-background">
        <div className="bg-shape shape-1"></div>
        <div className="bg-shape shape-2"></div>
        <div className="bg-shape shape-3"></div>
      </div>
      
      <div className="login-container">
        <div className="login-card">
          <div className="login-header">
            <div className="login-brand">
              <div className="brand-icon">🛡️</div>
              <h1>AI-NIDS</h1>
            </div>
            <p className="login-subtitle">Intrusion Detection System</p>
          </div>

          <form onSubmit={handleSubmit} className="login-form">
            {error && (
              <div className="login-error">
                <span className="error-icon">⚠️</span>
                {error}
              </div>
            )}

            <div className="form-group">
              <label htmlFor="email">Email Address</label>
              <div className="input-wrapper">
                <span className="input-icon">📧</span>
                <input
                  type="email"
                  id="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="Enter your email"
                  required
                  autoComplete="email"
                />
              </div>
            </div>

            <div className="form-group">
              <label htmlFor="password">Password</label>
              <div className="input-wrapper">
                <span className="input-icon">🔒</span>
                <input
                  type="password"
                  id="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                  required
                  autoComplete="current-password"
                />
              </div>
            </div>

            <button 
              type="submit" 
              className="login-button"
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <span className="spinner"></span>
                  Signing in...
                </>
              ) : (
                <>
                  <span className="btn-icon">→</span>
                  Sign In
                </>
              )}
            </button>

            <div className="demo-credentials">
              <p>Demo Credentials:</p>
              <code>admin@smartwebguard.com / admin123</code>
            </div>
          </form>

          <div className="login-footer">
            <p>🔒 Secure Login • AI-Powered Protection</p>
          </div>
        </div>

        <div className="login-info">
          <h2>Smart Web Guard</h2>
          <p>Advanced AI-powered network intrusion detection system</p>
          <ul className="features-list">
            <li>🤖 Real-time AI Threat Detection</li>
            <li>📊 Advanced Analytics Dashboard</li>
            <li>🔗 URL Safety Scanner</li>
            <li>📈 Predictive Analysis</li>
          </ul>
        </div>
      </div>
    </div>
  );
}

