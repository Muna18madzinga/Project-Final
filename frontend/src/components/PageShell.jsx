import { motion } from 'framer-motion'
import { componentStyles, typography } from '../styles/designSystem'

export default function PageShell({ icon: Icon, title, description, actions, children }) {
  return (
    <div className="space-y-6">
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2 }}
        className={componentStyles.card}
      >
        <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-4">
          <div className="flex items-center gap-4">
            {Icon && (
              <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.primary}`}>
                <Icon className="w-6 h-6" />
              </div>
            )}
            <div>
              <h1 className={typography.h2}>{title}</h1>
              {description && <p className={`${typography.small} mt-1`}>{description}</p>}
            </div>
          </div>
          {actions && <div className="flex items-center gap-3">{actions}</div>}
        </div>
      </motion.div>

      {children}
    </div>
  )
}
