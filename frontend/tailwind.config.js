/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          dark: '#070b14',
          card: '#0e1726',
          border: '#1e293b',
          accent: '#06b6d4', // Cyan
          emerald: '#10b981',
          rose: '#f43f5e',
          amber: '#f59e0b',
          blue: '#3b82f6',
          slate: '#334155'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'BlinkMacSystemFont', 'sans-serif'],
        mono: ['JetBrains Mono', 'Fira Code', 'monospace']
      }
    },
  },
  plugins: [],
}
