import axios from 'axios';
import { Scan, ScanListResponse } from '../types';

const BACKEND_URL = import.meta.env.PROD 
  ? 'https://basilisk-ja22.onrender.com' 
  : (import.meta.env.VITE_BACKEND_URL || 'http://localhost:8000');

export const createApiClient = (apiKey: string) => {
  return axios.create({
    baseURL: BACKEND_URL,
    headers: {
      Authorization: `Bearer ${apiKey}`,
    },
  });
};

export const getScans = async (
  apiKey: string,
  page: number = 1,
  perPage: number = 20
): Promise<ScanListResponse> => {
  const client = createApiClient(apiKey);
  const response = await client.get('/api/scans', { params: { page, per_page: perPage } });
  return response.data;
};

export const getScanDetail = async (scanId: number, apiKey: string): Promise<Scan> => {
  const client = createApiClient(apiKey);
  const response = await client.get(`/api/scans/${scanId}`);
  return response.data;
};

export const deleteScan = async (scanId: number, apiKey: string): Promise<void> => {
  const client = createApiClient(apiKey);
  await client.delete(`/api/scans/${scanId}`);
};
