export interface Finding {
  id: number;
  scan_id: number;
  vulnerability: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  description: string;
  target: string;
  attack_type?: string;
  payload?: string;
  created_at: string;
}

export interface Exploit {
  id: number;
  scan_id: number;
  payload: string;
  status_code: number | null;
  reason: string;
  created_at: string;
}

export interface Scan {
  id: number;
  user_id: number;
  target_url: string;
  pages_scanned: number;
  forms_found: number;
  vulnerable: boolean;
  mode: 'llm' | 'static';
  status: 'complete' | 'processing' | 'error';
  created_at: string;
  findings?: Finding[];
  exploits?: Exploit[];
}

export interface ScanListResponse {
  total: number;
  page: number;
  per_page: number;
  scans: Scan[];
}

export interface User {
  id: number;
  username: string;
  email: string;
  created_at: string;
}

export interface AuthContextType {
  apiKey: string | null;
  login: (apiKey: string) => void;
  logout: () => void;
}
