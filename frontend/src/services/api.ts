/**
 * Gupit Frontend API Client.
 * Connects to the FastAPI backend conforming to docs/API_CONTRACT.md.
 */

import { HealthStatus } from '../types';

const API_BASE = '/api';

/**
 * Fetch health status of the Gupit backend.
 */
export async function fetchHealth(): Promise<HealthStatus> {
  const response = await fetch(`${API_BASE}/health`, {
    method: 'GET',
    headers: {
      'Accept': 'application/json',
    },
  });

  if (!response.ok) {
    throw new Error(`Health check failed with status: ${response.status}`);
  }

  return response.json();
}
