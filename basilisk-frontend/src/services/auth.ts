import axios from 'axios';

const BACKEND_URL = import.meta.env.PROD 
  ? 'https://basilisk-ja22.onrender.com' 
  : (import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000');

export const requestDeviceCode = async () => {
  const res = await axios.post(`${BACKEND_URL}/api/auth/device-code`);
  return res.data;
};

export const verifyUserInBrowser = async (
  user_code: string,
  username: string,
  email: string
): Promise<{ verified: boolean; api_key: string; username: string }> => {
  const res = await axios.post(`${BACKEND_URL}/api/auth/verify`, {
    user_code,
    username,
    email,
  });
  return res.data;
};

export const pollForApiKey = async (device_code: string) => {
  const res = await axios.post(`${BACKEND_URL}/api/auth/token`, { device_code });
  return res.data;
};

export const saveApiKeyLocally = (key: string, username?: string) => {
  localStorage.setItem('basilisk_api_key', key);
  if (username) {
    localStorage.setItem('basilisk_username', username);
  }
};

export const loadApiKeyFromStorage = (): string | null => {
  return localStorage.getItem('basilisk_api_key');
};

export const loadUsernameFromStorage = (): string | null => {
  return localStorage.getItem('basilisk_username');
};

export const clearAuth = () => {
  localStorage.removeItem('basilisk_api_key');
  localStorage.removeItem('basilisk_username');
};
