/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './src/pages/**/*.{js,ts,jsx,tsx,mdx}',
    './src/components/**/*.{js,ts,jsx,tsx,mdx}',
    './src/app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        background: '#0B0F19',
        surface: '#111827',
        card: '#1F2937',
        border: '#374151',
        primary: {
          50: '#ECFEFF',
          500: '#06B6D4',
          600: '#0891B2',
          700: '#0E7490',
        },
        cyber: {
          critical: '#EF4444',
          high: '#F97316',
          medium: '#EAB308',
          low: '#38BDF8',
          info: '#94A3B8',
          safe: '#10B981',
        },
      },
    },
  },
  plugins: [],
};
