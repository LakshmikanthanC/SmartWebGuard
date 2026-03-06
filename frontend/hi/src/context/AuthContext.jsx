import React, { createContext, useContext, useState, useEffect } from "react";

const AuthContext = createContext(null);

const DEMO_USER = {
  email: "admin@smartwebguard.com",
  password: "admin123",
  name: "Administrator",
  role: "admin"
};

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Check for existing session
    const storedUser = localStorage.getItem("swg_user");
    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser));
      } catch (e) {
        localStorage.removeItem("swg_user");
      }
    }
    setLoading(false);
  }, []);

  const login = async (email, password) => {
    // Simulate API call - in production, this would call backend
    return new Promise((resolve, reject) => {
      setTimeout(() => {
        if (email === DEMO_USER.email && password === DEMO_USER.password) {
          const userData = { 
            email: DEMO_USER.email, 
            name: DEMO_USER.name, 
            role: DEMO_USER.role 
          };
          setUser(userData);
          localStorage.setItem("swg_user", JSON.stringify(userData));
          resolve(userData);
        } else {
          reject(new Error("Invalid email or password"));
        }
      }, 800);
    });
  };

  const logout = () => {
    setUser(null);
    localStorage.removeItem("swg_user");
  };

  const isAuthenticated = !!user;

  return (
    <AuthContext.Provider value={{ user, login, logout, isAuthenticated, loading }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}

export default AuthContext;

