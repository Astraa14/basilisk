export interface Finding {
  id: number;
  scan_id: number;
  vulnerability: string;
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
  description: string;
  target: string;
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
