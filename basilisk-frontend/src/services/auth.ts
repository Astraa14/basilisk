import axios from 'axios';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

export const requestDeviceCode = async () => {
  const res = await axios.post(`${BACKEND_URL}/api/auth/device-code`);
  return res.data; // { device_code, user_code, verification_uri, expires_in }
};

export const verifyUserInBrowser = async (user_code: string, username: string, email: string) => {
  const res = await axios.post(`${BACKEND_URL}/api/auth/verify`, {
    user_code,
    username,
    email,
  });
  return res.data;
};

export const pollForApiKey = async (device_code: string) => {
  const res = await axios.post(`${BACKEND_URL}/api/auth/token`, { device_code });
  return res.data; // { status, api_key, username }
};

export const saveApiKeyLocally = (key: string) => {
  localStorage.setItem('basilisk_api_key', key);
};

export const loadApiKeyFromStorage = (): string | null => {
  return localStorage.getItem('basilisk_api_key');
};

export const clearAuth = () => {
  localStorage.removeItem('basilisk_api_key');
};
