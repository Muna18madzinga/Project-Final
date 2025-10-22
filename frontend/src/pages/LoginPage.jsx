import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { AppWindow, LogIn, Eye, EyeOff, AlertCircle } from 'lucide-react'
import { useAuthStore } from '../store/authStore'
import toast from 'react-hot-toast'
import { componentStyles, typography } from '../styles/designSystem'

export default function LoginPage() {
  const navigate = useNavigate()
  const { login, verifyMFA, mfaRequired } = useAuthStore()

  const [formData, setFormData] = useState({
    username: '',
    password: '',
    mfaCode: ''
  })
  const [showPassword, setShowPassword] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (e) => {
    e.preventDefault()
    setError('')
    setLoading(true)

    try {
      if (mfaRequired) {
        // Verify MFA code
        await verifyMFA(formData.mfaCode)
        toast.success('Login successful!')
        navigate('/')
      } else {
        // Initial login
        const result = await login(formData.username, formData.password)

        if (result.mfaRequired) {
          toast.success('Please enter your MFA code')
        } else {
          toast.success('Login successful!')
          navigate('/')
        }
      }
    } catch (err) {
      setError(err.message)
      toast.error(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50 px-4">
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="w-full max-w-md"
      >
        {/* Logo and Title */}
        <div className="text-center mb-8">
          <motion.div
            initial={{ scale: 0.8, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            transition={{ duration: 0.3 }}
            className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.primary} mx-auto mb-4`}
          >
            <AppWindow className="w-7 h-7" />
          </motion.div>
          <h1 className={typography.h1 + ' mb-2'}>
            Operations Console
          </h1>
          <p className={typography.small}>
            {mfaRequired ? 'Enter your verification code' : 'Sign in to your account'}
          </p>
        </div>

        {/* Login Card */}
        <div className={componentStyles.card}>
          <form onSubmit={handleSubmit} className="space-y-6">
            {!mfaRequired ? (
              <>
                {/* Username Input */}
                <div>
                  <label htmlFor="username" className="block text-sm font-medium text-gray-700 mb-2">
                    Username
                  </label>
                  <input
                    id="username"
                    type="text"
                    required
                    value={formData.username}
                    onChange={(e) => setFormData({ ...formData, username: e.target.value })}
                    className={componentStyles.input.base}
                    placeholder="Enter your username"
                  />
                </div>

                {/* Password Input */}
                <div>
                  <label htmlFor="password" className="block text-sm font-medium text-gray-700 mb-2">
                    Password
                  </label>
                  <div className="relative">
                    <input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      required
                      value={formData.password}
                      onChange={(e) => setFormData({ ...formData, password: e.target.value })}
                      className={componentStyles.input.base + ' pr-12'}
                      placeholder="Enter your password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-700 transition"
                    >
                      {showPassword ? <EyeOff className="w-5 h-5" /> : <Eye className="w-5 h-5" />}
                    </button>
                  </div>
                </div>
              </>
            ) : (
              /* MFA Code Input */
              <div>
                <label htmlFor="mfaCode" className="block text-sm font-medium text-gray-700 mb-2">
                  6-Digit Code
                </label>
                <input
                  id="mfaCode"
                  type="text"
                  required
                  maxLength={6}
                  value={formData.mfaCode}
                  onChange={(e) => setFormData({ ...formData, mfaCode: e.target.value.replace(/\D/g, '') })}
                  className={componentStyles.input.base + ' text-center text-2xl font-mono tracking-widest'}
                  placeholder="000000"
                />
                <p className={typography.small + ' mt-2'}>
                  Enter the 6-digit code from your authenticator app
                </p>
              </div>
            )}

            {/* Error Message */}
            {error && (
              <motion.div
                initial={{ opacity: 0, y: -10 }}
                animate={{ opacity: 1, y: 0 }}
                className="flex items-center gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700"
              >
                <AlertCircle className="w-5 h-5 flex-shrink-0" />
                <span className={typography.small}>{error}</span>
              </motion.div>
            )}

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className={`${componentStyles.button.base} ${componentStyles.button.primary} w-full flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              {loading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Verifying...</span>
                </>
              ) : (
                <>
                  <LogIn className="w-5 h-5" />
                  <span>{mfaRequired ? 'Verify Code' : 'Sign In'}</span>
                </>
              )}
            </button>
          </form>

          {/* Links */}
          {!mfaRequired && (
            <div className="mt-6 text-center space-y-2">
              <p className="text-sm text-gray-600">
                Don't have an account?{' '}
                <Link to="/register" className="text-blue-600 hover:text-blue-700 font-semibold">
                  Sign up
                </Link>
              </p>
              <button className="text-sm text-gray-500 hover:text-gray-700">
                Forgot password?
              </button>
            </div>
          )}
        </div>

      </motion.div>
    </div>
  )
}
