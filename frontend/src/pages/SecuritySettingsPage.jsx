import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Settings2, ToggleLeft, ToggleRight, Shield, Save } from 'lucide-react'
import toast from 'react-hot-toast'
import PageShell from '../components/PageShell'
import { componentStyles, typography } from '../styles/designSystem'
import api from '../services/api'

const settingDefinitions = [
  {
    key: 'mfa',
    label: 'Require MFA for administrators',
    description: 'Enforce multi-factor authentication on privileged accounts.'
  },
  {
    key: 'sessionTimeout',
    label: 'Log out inactive users after 30 minutes',
    description: 'Protect sessions by expiring tokens when idle for extended periods.'
  },
  {
    key: 'emailAlerts',
    label: 'Send email alerts on critical events',
    description: 'Notify the on-call rotation immediately when high priority alerts occur.'
  }
]

export default function SecuritySettingsPage() {
  const [settings, setSettings] = useState({
    mfa: true,
    sessionTimeout: true,
    emailAlerts: false
  })
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    const loadSettings = async () => {
      try {
        const response = await api.get('security/settings')
        setSettings(response.data?.settings || settings)
      } catch (error) {
        console.error('Failed to load security settings', error)
        toast.error('Unable to load security settings')
      } finally {
        setLoading(false)
      }
    }
    loadSettings()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const toggleSetting = (key) => {
    setSettings((prev) => ({ ...prev, [key]: !prev[key] }))
  }

  const handleSave = async () => {
    try {
      setSaving(true)
      await api.post('security/settings', settings)
      toast.success('Security settings saved')
    } catch (error) {
      console.error('Failed to save security settings', error)
      toast.error(error.response?.data?.message || 'Failed to save settings')
    } finally {
      setSaving(false)
    }
  }

  return (
    <PageShell
      icon={Settings2}
      title="Security Controls"
      description="Adjust baseline policies for authentication and alerting."
      actions={
        <button
          type="button"
          onClick={handleSave}
          disabled={saving}
          className={`${componentStyles.button.base} ${componentStyles.button.primary}`}
        >
          <Save className="w-4 h-4 mr-2" />
          {saving ? 'Saving…' : 'Save changes'}
        </button>
      }
    >
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
        className={componentStyles.card}
      >
        <div className="space-y-6">
          {settingDefinitions.map(({ key, label, description }) => {
            const enabled = settings[key]
            const ToggleIcon = enabled ? ToggleRight : ToggleLeft

            return (
              <button
                key={key}
                type="button"
                onClick={() => toggleSetting(key)}
                className="w-full flex items-start justify-between gap-4 text-left"
                disabled={loading || saving}
              >
                <div>
                  <p className="text-sm font-semibold text-gray-900">{label}</p>
                  <p className={typography.small}>{description}</p>
                </div>
                <ToggleIcon className={`w-10 h-10 ${enabled ? 'text-blue-600' : 'text-gray-400'}`} />
              </button>
            )
          })}
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className={componentStyles.card}
      >
        <div className="flex items-center gap-3 mb-3">
          <Shield className="w-5 h-5 text-blue-600" />
          <h2 className={typography.h4}>Security posture</h2>
        </div>
        <p className={typography.small}>
          Adjusting these controls affects how quickly the system notifies administrators and how defensive the
          platform is about user access. Review the incident response policy when adopting stricter settings.
        </p>
      </motion.div>
    </PageShell>
  )
}
