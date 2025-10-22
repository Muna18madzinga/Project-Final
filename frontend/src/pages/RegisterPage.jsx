import { useState } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import { motion } from 'framer-motion'
import { UserPlus, Mail, Lock, AlertCircle, CheckCircle2 } from 'lucide-react'
import toast from 'react-hot-toast'
import PageShell from '../components/PageShell'
import { componentStyles, typography } from '../styles/designSystem'
import { useAuthStore } from '../store/authStore'

export default function RegisterPage() {
  const navigate = useNavigate()
  const { register } = useAuthStore()

  const [formData, setFormData] = useState({
    username: '',
    email: '',
    password: ''
  })
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleSubmit = async (event) => {
    event.preventDefault()
    setError('')
    setLoading(true)

    try {
      await register(formData.username, formData.password, formData.email)
      toast.success('Account created. You can sign in now.')
      navigate('/login')
    } catch (err) {
      const message = err.message || 'Registration failed'
      setError(message)
      toast.error(message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="max-w-3xl mx-auto">
      <PageShell
        icon={UserPlus}
        title="Create Account"
        description="Set up your operator profile to access the console."
      >
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25 }}
          className={componentStyles.card}
        >
          <form onSubmit={handleSubmit} className="space-y-6">
            <div className="grid grid-cols-1 gap-4">
              <label className="block">
                <span className="text-sm font-medium text-gray-700">Username</span>
                <div className="mt-1 relative">
                  <input
                    type="text"
                    required
                    autoComplete="username"
                    value={formData.username}
                    onChange={(event) =>
                      setFormData((prev) => ({ ...prev, username: event.target.value }))
                    }
                    className={`${componentStyles.input.base} pr-12`}
                    placeholder="Choose a username"
                  />
                  <CheckCircle2 className="w-5 h-5 absolute right-3 top-1/2 -translate-y-1/2 text-gray-400" />
                </div>
              </label>

              <label className="block">
                <span className="text-sm font-medium text-gray-700">Email</span>
                <div className="mt-1 relative">
                  <input
                    type="email"
                    required
                    autoComplete="email"
                    value={formData.email}
                    onChange={(event) =>
                      setFormData((prev) => ({ ...prev, email: event.target.value }))
                    }
                    className={`${componentStyles.input.base} pr-12`}
                    placeholder="name@example.com"
                  />
                  <Mail className="w-5 h-5 absolute right-3 top-1/2 -translate-y-1/2 text-gray-400" />
                </div>
              </label>

              <label className="block">
                <span className="text-sm font-medium text-gray-700">Password</span>
                <div className="mt-1 relative">
                  <input
                    type="password"
                    required
                    autoComplete="new-password"
                    value={formData.password}
                    onChange={(event) =>
                      setFormData((prev) => ({ ...prev, password: event.target.value }))
                    }
                    className={`${componentStyles.input.base} pr-12`}
                    placeholder="Enter a secure password"
                  />
                  <Lock className="w-5 h-5 absolute right-3 top-1/2 -translate-y-1/2 text-gray-400" />
                </div>
              </label>
            </div>

            {error && (
              <div className="flex items-center gap-2 p-4 bg-red-50 border border-red-200 rounded-lg text-red-700">
                <AlertCircle className="w-5 h-5" />
                <span className={typography.small}>{error}</span>
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              className={`${componentStyles.button.base} ${componentStyles.button.primary} w-full flex items-center justify-center gap-2 disabled:opacity-50 disabled:cursor-not-allowed`}
            >
              {loading ? (
                <>
                  <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin" />
                  <span>Creating account...</span>
                </>
              ) : (
                <>
                  <UserPlus className="w-5 h-5" />
                  <span>Sign Up</span>
                </>
              )}
            </button>
          </form>
          <div className="mt-6 text-center">
            <p className={typography.small}>
              Already registered?{' '}
              <Link to="/login" className="text-blue-600 hover:text-blue-700 font-semibold">
                Back to sign in
              </Link>
            </p>
          </div>
        </motion.div>
      </PageShell>
    </div>
  )
}
