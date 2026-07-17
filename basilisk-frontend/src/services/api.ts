import axios from 'axios';
import { Scan } from '../types';

const BACKEND_URL = import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000';

export const createApiClient = (apiKey: string) => {
  return axios.create({
    baseURL: BACKEND_URL,
    headers: {
      Authorization: `Bearer ${apiKey}`,
    },
  });
};

export const getScans = async (apiKey: string): Promise<Scan[]> => {
  const client = createApiClient(apiKey);
  const response = await client.get('/api/scans');
  return response.data;
};

export const getScanDetail = async (scanId: number, apiKey: string): Promise<Scan> => {
  const client = createApiClient(apiKey);
  const response = await client.get(`/api/scans/${scanId}`);
  return response.data;
};
