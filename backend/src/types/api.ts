export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: {
    code: string;
    message: string;
    request_id?: string;
    timestamp?: string;
    details?: any[];
  };
}
