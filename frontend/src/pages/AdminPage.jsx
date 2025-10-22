import { motion } from 'framer-motion'
import { useState } from 'react'
import { UserCog, UserPlus, ListChecks, ClipboardList } from 'lucide-react'
import toast from 'react-hot-toast'
import PageShell from '../components/PageShell'
import { componentStyles, typography } from '../styles/designSystem'
import api from '../services/api'

const tasks = [
  {
    key: 'invite_operator',
    title: 'Invite operator',
    description: 'Send an invitation email to a new operator account.',
    icon: UserPlus
  },
  {
    key: 'review_access',
    title: 'Review access',
    description: 'Audit permissions and remove access no longer required.',
    icon: ListChecks
  },
  {
    key: 'download_compliance_log',
    title: 'Compliance log',
    description: 'Download the latest admin audit log for compliance reporting.',
    icon: ClipboardList
  }
]

export default function AdminPage() {
  const [workingAction, setWorkingAction] = useState(null)

  const runAdminAction = async (actionKey) => {
    try {
      setWorkingAction(actionKey)
      const response = await api.post('admin/actions', { action: actionKey })
      const message = response.data?.message || 'Action completed'
      toast.success(message)

      if (actionKey === 'download_compliance_log') {
        const blob = new Blob([JSON.stringify(response.data?.log || [], null, 2)], {
          type: 'application/json'
        })
        const url = URL.createObjectURL(blob)
        const link = document.createElement('a')
        link.href = url
        link.download = `compliance-log-${Date.now()}.json`
        document.body.appendChild(link)
        link.click()
        link.remove()
        URL.revokeObjectURL(url)
      }
    } catch (error) {
      toast.error(error.response?.data?.message || 'Action failed')
      console.error('Admin action failed', error)
    } finally {
      setWorkingAction(null)
    }
  }

  return (
    <PageShell
      icon={UserCog}
      title="Administration"
      description="Oversee operator access and platform governance."
    >
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
        className={componentStyles.card}
      >
        <div className="space-y-6">
          {tasks.map(({ key, title, description, icon: Icon }) => (
            <div key={key} className="flex items-start gap-4">
              <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.accent}`}>
                <Icon className="w-5 h-5" />
              </div>
              <div>
                <p className="text-sm font-semibold text-gray-900">{title}</p>
                <p className={typography.small}>{description}</p>
                <button
                  type="button"
                  onClick={() => runAdminAction(key)}
                  disabled={workingAction === key}
                  className={`${componentStyles.button.base} ${componentStyles.button.secondary} mt-3 text-xs`}
                >
                  {workingAction === key ? 'Working…' : 'Open action'}
                </button>
              </div>
            </div>
          ))}
        </div>
      </motion.div>
    </PageShell>
  )
}
