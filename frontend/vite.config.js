export default defineConfig({
  plugins: [react()],
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://localhost:8001', // Changed from 8000 to 8001
        changeOrigin: true,
        secure: false
      }
    }
  }
})

