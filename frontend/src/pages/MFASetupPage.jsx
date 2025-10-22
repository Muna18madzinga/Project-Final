import { motion } from 'framer-motion'
import { ShieldCheck, Smartphone, RefreshCcw, KeyRound } from 'lucide-react'
import PageShell from '../components/PageShell'
import { componentStyles, typography } from '../styles/designSystem'

const steps = [
  {
    title: 'Install an authenticator app',
    description: 'Use any TOTP compatible app such as Microsoft Authenticator, 1Password, or Authy.',
    icon: Smartphone
  },
  {
    title: 'Scan the QR code',
    description: 'Use the app to scan the QR code provided during setup. This links the console to your device.',
    icon: RefreshCcw
  },
  {
    title: 'Enter the verification code',
    description: 'Type the 6-digit rotating code from your authenticator app to confirm the setup.',
    icon: KeyRound
  }
]

export default function MFASetupPage() {
  return (
    <PageShell
      icon={ShieldCheck}
      title="Multi-factor Authentication"
      description="Secure your operator access by pairing an authenticator application."
      actions={
        <button
          type="button"
          className={`${componentStyles.button.base} ${componentStyles.button.primary}`}
        >
          Continue setup
        </button>
      }
    >
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.25 }}
          className={`lg:col-span-2 ${componentStyles.card}`}
        >
          <div className="space-y-6">
            {steps.map(({ title, description, icon: Icon }, index) => (
              <div key={title} className="flex items-start gap-4">
                <div
                  className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.primary}`}
                >
                  <Icon className="w-5 h-5" />
                </div>
                <div>
                  <p className="text-sm font-semibold text-gray-900">
                    Step {index + 1}: {title}
                  </p>
                  <p className={typography.small}>{description}</p>
                </div>
              </div>
            ))}
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className={componentStyles.card}
        >
          <div className="space-y-4">
            <p className={typography.h4}>Need help?</p>
            <p className={typography.small}>
              If you do not see a QR code, request a fresh setup token from the administrator. Each token
              is valid for 10 minutes.
            </p>
            <div className="p-4 rounded-lg border border-dashed border-gray-300 text-center">
              <p className="text-sm font-semibold text-gray-700 mb-2">Time-based code</p>
              <p className="text-2xl font-mono text-gray-900 tracking-widest">
                000000
              </p>
              <p className="text-xs text-gray-500 mt-2">Codes refresh every 30 seconds</p>
            </div>
            <button
              type="button"
              className={`${componentStyles.button.base} ${componentStyles.button.secondary} w-full`}
            >
              View recovery options
            </button>
          </div>
        </motion.div>
      </div>
    </PageShell>
  )
}
