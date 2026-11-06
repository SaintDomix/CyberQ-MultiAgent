import { defineConfig } from 'vite';
export default defineConfig({server:{port:5173,proxy:{'/api':'http://127.0.0.1:8001','/report.html':'http://127.0.0.1:8001'}},build:{outDir:'dist'}});
