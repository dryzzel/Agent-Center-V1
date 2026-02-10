import { CONFIG } from './config.js';
import io from 'socket.io-client';

// Setup Socket.io connection
export const socket = io(CONFIG.API_BASE_URL);

socket.on('connect', () => {
    console.log('Connected to Socket.io server');
});

// We can add more specific listeners here or export socket to let others add them
export function setupSocketListeners() {
    socket.on('lead_updated', (data) => {
        console.log('Lead updated:', data);
        // Dispatch a custom event so other modules can react without tight coupling
        window.dispatchEvent(new CustomEvent('lead_updated', { detail: data }));
    });
}
