// Design System - Uniform styling constants for the application

export const colors = {
  // Primary palette
  primary: {
    50: '#eff6ff',
    100: '#dbeafe',
    200: '#bfdbfe',
    300: '#93c5fd',
    400: '#60a5fa',
    500: '#3b82f6',
    600: '#2563eb',
    700: '#1d4ed8',
    800: '#1e40af',
    900: '#1e3a8a',
  },

  // Neutral/Gray palette
  gray: {
    50: '#f9fafb',
    100: '#f3f4f6',
    200: '#e5e7eb',
    300: '#d1d5db',
    400: '#9ca3af',
    500: '#6b7280',
    600: '#4b5563',
    700: '#374151',
    800: '#1f2937',
    900: '#111827',
  },

  // Status colors
  success: '#10b981',
  warning: '#f59e0b',
  error: '#ef4444',
  info: '#3b82f6',
}

export const spacing = {
  xs: '0.25rem',    // 4px
  sm: '0.5rem',     // 8px
  md: '1rem',       // 16px
  lg: '1.5rem',     // 24px
  xl: '2rem',       // 32px
  '2xl': '3rem',    // 48px
  '3xl': '4rem',    // 64px
}

export const borderRadius = {
  sm: '0.375rem',   // 6px
  md: '0.5rem',     // 8px
  lg: '0.75rem',    // 12px
  xl: '1rem',       // 16px
  '2xl': '1.5rem',  // 24px
  full: '9999px',
}

export const shadows = {
  sm: '0 1px 2px 0 rgb(0 0 0 / 0.05)',
  md: '0 4px 6px -1px rgb(0 0 0 / 0.1), 0 2px 4px -2px rgb(0 0 0 / 0.1)',
  lg: '0 10px 15px -3px rgb(0 0 0 / 0.1), 0 4px 6px -4px rgb(0 0 0 / 0.1)',
  xl: '0 20px 25px -5px rgb(0 0 0 / 0.1), 0 8px 10px -6px rgb(0 0 0 / 0.1)',
}

// Reusable component styles
export const componentStyles = {
  // Card style
  card: 'bg-white rounded-xl p-6 shadow-md border border-gray-200',

  // Layout scaffolding
  layout: {
    shell: 'min-h-screen bg-gray-100',
    container: 'flex flex-col md:flex-row min-h-screen',
    sidebar: 'w-full md:w-64 bg-white border-b md:border-b-0 md:border-r border-gray-200',
    contentArea: 'flex-1 bg-gray-50',
    contentInner: 'max-w-6xl mx-auto px-4 py-8'
  },

  // Button styles
  button: {
    base: 'px-4 py-2 rounded-lg font-medium transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2',
    primary: 'bg-blue-600 text-white hover:bg-blue-700 focus:ring-blue-500',
    secondary: 'bg-gray-200 text-gray-800 hover:bg-gray-300 focus:ring-gray-500',
    danger: 'bg-red-600 text-white hover:bg-red-700 focus:ring-red-500',
    success: 'bg-green-600 text-white hover:bg-green-700 focus:ring-green-500',
  },

  // Input styles
  input: {
    base: 'w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent transition duration-200',
    error: 'border-red-500 focus:ring-red-500',
  },

  // Badge/Tag styles
  badge: {
    base: 'px-3 py-1 rounded-full text-xs font-semibold',
    success: 'bg-green-100 text-green-700',
    warning: 'bg-yellow-100 text-yellow-700',
    error: 'bg-red-100 text-red-700',
    info: 'bg-blue-100 text-blue-700',
    neutral: 'bg-gray-100 text-gray-700',
  },

  // Severity indicators
  severity: {
    critical: {
      bg: 'bg-red-100',
      text: 'text-red-700',
      border: 'border-red-300',
      icon: 'text-red-600',
    },
    high: {
      bg: 'bg-red-100',
      text: 'text-red-700',
      border: 'border-red-300',
      icon: 'text-red-600',
    },
    medium: {
      bg: 'bg-orange-100',
      text: 'text-orange-700',
      border: 'border-orange-300',
      icon: 'text-orange-600',
    },
    low: {
      bg: 'bg-yellow-100',
      text: 'text-yellow-700',
      border: 'border-yellow-300',
      icon: 'text-yellow-600',
    },
  },

  // Navigation styles
  navLink: {
    base: 'flex items-center gap-3 px-4 py-3 rounded-lg text-sm font-medium text-gray-600 hover:text-blue-600 hover:bg-blue-50 transition-colors',
    active: 'text-blue-600 bg-blue-50 border border-blue-100'
  },

  // Icon containers for stat blocks
  statIcon: {
    base: 'rounded-lg w-12 h-12 flex items-center justify-center',
    primary: 'bg-blue-600 text-white',
    accent: 'bg-indigo-600 text-white',
    success: 'bg-emerald-600 text-white',
    neutral: 'bg-gray-800 text-white'
  },
}

// Typography
export const typography = {
  h1: 'text-3xl font-bold text-gray-900',
  h2: 'text-2xl font-bold text-gray-900',
  h3: 'text-xl font-bold text-gray-900',
  h4: 'text-lg font-semibold text-gray-900',
  body: 'text-base text-gray-700',
  small: 'text-sm text-gray-600',
  caption: 'text-xs text-gray-500',
}
