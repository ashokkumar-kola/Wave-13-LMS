import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
} from "react";
import axios from "axios";
import { jwtDecode } from "jwt-decode";
import { useNavigate } from "react-router-dom";

export const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const navigate = useNavigate();

  // Load initial state from localStorage
  const [accessToken, setAccessToken] = useState(
    () => localStorage.getItem("accessToken") || null
  );
  const [user, setUser] = useState(() => {
    const storedUser = localStorage.getItem("user");
    return storedUser ? JSON.parse(storedUser) : null;
  });
  const [role, setRole] = useState(() => localStorage.getItem("role") || null);
  const [userName, setUserName] = useState(
    () => localStorage.getItem("userName") || null
  );
  const [loading, setLoading] = useState(true);

  // Base URL
  const BASE_URL = process.env.REACT_APP_API_URL || "http://localhost:8000";

  // getBaseURL - stable
  const getBaseURL = useCallback(
    (r) => {
      // same for all roles now - change if role-based paths needed
      return `${BASE_URL}/api/auth`;
    },
    [BASE_URL]
  );

  // getApiInstance - stable
  const getApiInstance = useCallback(
    (r) =>
      axios.create({
        baseURL: getBaseURL(r),
        withCredentials: true,
      }),
    [getBaseURL]
  );

  // JWT decode helper (uses named export jwtDecode)
  const decodeToken = (token) => {
    try {
      return jwtDecode(token);
    } catch (error) {
      console.error("Error decoding token:", error);
      return null;
    }
  };

  // Sign-up
  const signUp = async ({ username, email, password, role }) => {
    try {
      const api = getApiInstance(role);
      const res = await api.post("/signup", {
        username,
        email,
        password,
        role,
      });
      return res.data;
    } catch (error) {
      const msg =
        error.response?.data?.message ||
        error.response?.data?.detail ||
        error.message ||
        "Signup failed";
      throw new Error(msg);
    }
  };

  // Login
  const login = async ({ email, password, role: roleParam }) => {
    try {
      const api = getApiInstance(roleParam);

      const formData = new URLSearchParams();
      formData.append("username", email);
      formData.append("password", password);

      const res = await api.post("/login", formData, {
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
      });

      console.log("login response:", res);

      const token = res.data?.access_token;
      const userData = res.data?.user || {};
      const userrole = userData?.role || roleParam || null;

      // handle is_active present either at top-level or inside user
      const isActiveRaw = res.data?.is_active ?? userData?.is_active;
      const isApproved = isActiveRaw === true || isActiveRaw === "true";

      console.log("isApproved:", isApproved);

      if (!isApproved) {
        throw new Error("Not approved yet");
      }

      // store token & user details (server user object is canonical)
      setAccessToken(token);
      setUser(userData);
      setUserName(userData?.username || null);
      setRole(userrole);

      localStorage.setItem("accessToken", token);
      localStorage.setItem("user", JSON.stringify(userData));
      if (userrole) localStorage.setItem("role", userrole);
      if (userData?.username) localStorage.setItem("userName", userData.username);

      return res.data;
    } catch (error) {
      console.error("Login failed:", error.response?.data || error.message);
      const msg =
        error.response?.data?.detail ||
        error.response?.data?.message ||
        error.message ||
        "Error logging in";
      throw new Error(msg);
    }
  };

  // Logout - wrapped in useCallback so it is stable for deps
  const logout = useCallback(async () => {
    try {
      const userRole = localStorage.getItem("role") || role;
      // Clear local state and storage first (defensive)
      setAccessToken(null);
      setUser(null);
      setRole(null);
      setUserName(null);
      localStorage.clear();

      if (!userRole) {
        navigate("/login");
        return;
      }

      const api = getApiInstance(userRole);
      try {
        // endpoint relative to baseURL (/api/auth), call /logout
        await api.post("/logout");
      } catch (err) {
        // don't block navigation if logout request fails
        console.warn("Logout request failed (server):", err.response?.data || err.message);
      }

      navigate("/login");
    } catch (error) {
      console.error("Logout error:", error.response?.data?.message || error.message);
    }
  }, [getApiInstance, navigate, role]);

  // Refresh access token - stable; depends on BASE_URL and logout
  const refreshAccessToken = useCallback(async () => {
    try {
      const res = await axios.post(
        `${BASE_URL}/api/auth/refresh-token`,
        {},
        { withCredentials: true }
      );
      const token = res.data?.access_token;
      if (!token) throw new Error("No refresh token returned");

      setAccessToken(token);

      const decodedUser = decodeToken(token) || null;
      if (decodedUser) {
        setUser(decodedUser);
        localStorage.setItem("user", JSON.stringify(decodedUser));
      }
      localStorage.setItem("accessToken", token);

      return token;
    } catch (error) {
      console.error("Failed to refresh token:", error.response?.data || error.message);
      await logout();
      return null;
    }
  }, [BASE_URL, logout]);

  // Setup API interceptors for automatic token refresh on 401
  useEffect(() => {
    if (!role) return;

    const api = getApiInstance(role);

    const interceptor = api.interceptors.response.use(
      (response) => response,
      async (error) => {
        // try refresh only once per failed request
        const status = error.response?.status;
        if (status === 401 && !error.config?._retry) {
          error.config._retry = true;
          try {
            const newAccessToken = await refreshAccessToken();
            if (newAccessToken) {
              error.config.headers = error.config.headers || {};
              error.config.headers["Authorization"] = `Bearer ${newAccessToken}`;
              return api(error.config);
            }
          } catch (refreshError) {
            console.error("Failed to refresh token in interceptor:", refreshError);
            await logout();
          }
        }
        return Promise.reject(error);
      }
    );

    return () => {
      try {
        api.interceptors.response.eject(interceptor);
      } catch (e) {
        // ignore
      }
    };
  }, [role, getApiInstance, refreshAccessToken, logout]);

  // Restore auth state on page reload
  useEffect(() => {
    const storedToken = localStorage.getItem("accessToken");
    const storedUser = localStorage.getItem("user");

    if (storedToken) {
      setAccessToken(storedToken);
    }

    if (storedUser) {
      try {
        setUser(JSON.parse(storedUser));
      } catch (e) {
        setUser(null);
      }
    }

    setRole(localStorage.getItem("role") || null);
    setUserName(localStorage.getItem("userName") || null);

    setLoading(false);
  }, []);

  // isAuthenticated helper
  const isAuthenticated = () => !!accessToken && !!user;

  return (
    <AuthContext.Provider
      value={{
        accessToken,
        userName,
        user,
        role,
        login,
        signUp,
        logout,
        loading,
        isAuthenticated,
        api: getApiInstance(role),
        refreshAccessToken,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

// Custom hook
export const useAuth = () => useContext(AuthContext);

export default AuthContext;
