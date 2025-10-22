import { Outlet, NavLink, useLocation } from 'react-router-dom'
import { LayoutDashboard, Bell, MonitorSmartphone, Settings, Users, AppWindow } from 'lucide-react'
import { useAuthStore } from '../../store/authStore'
import { componentStyles, typography } from '../../styles/designSystem'

const navItems = [
  { label: 'Overview', to: '/', icon: LayoutDashboard, exact: true },
  { label: 'Alerts', to: '/threats', icon: Bell },
  { label: 'Devices', to: '/devices', icon: MonitorSmartphone },
  { label: 'Settings', to: '/settings', icon: Settings },
  { label: 'Admin', to: '/admin', icon: Users }
]

export default function DashboardLayout() {
  const location = useLocation()
  const { user, logout } = useAuthStore()

  const activeNav = navItems.find((item) =>
    item.exact ? location.pathname === item.to : location.pathname.startsWith(item.to)
  )

  return (
    <div className={componentStyles.layout.shell}>
      <div className={componentStyles.layout.container}>
        <aside className={componentStyles.layout.sidebar}>
          <div className="px-4 py-6 border-b border-gray-200">
            <div className="flex items-center gap-3">
              <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.primary}`}>
                <AppWindow className="w-6 h-6" />
              </div>
              <div>
                <p className="text-sm font-semibold text-gray-900">Operations Console</p>
                <p className={typography.caption}>Unified system overview</p>
              </div>
            </div>
          </div>

          <nav className="px-4 py-6 space-y-1">
            {navItems.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.exact}
                className={({ isActive }) =>
                  `${componentStyles.navLink.base} ${isActive ? componentStyles.navLink.active : ''}`
                }
              >
                <item.icon className="w-4 h-4" />
                {item.label}
              </NavLink>
            ))}
          </nav>
        </aside>

        <main className={componentStyles.layout.contentArea}>
          <header className="bg-white border-b border-gray-200">
            <div className="max-w-6xl mx-auto px-4 py-4 flex items-center justify-between">
              <div>
                <p className={typography.caption}>Current view</p>
                <h1 className={typography.h2}>{activeNav?.label || 'Dashboard'}</h1>
              </div>
              <div className="flex items-center gap-4">
                <div className="flex items-center gap-3">
                  <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.neutral}`}>
                    {(user?.username?.[0] || 'U').toUpperCase()}
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-gray-900">
                      {user?.username || 'User'}
                    </p>
                    <p className={typography.caption}>Signed in</p>
                  </div>
                </div>
                <button
                  type="button"
                  onClick={logout}
                  className={`${componentStyles.button.base} ${componentStyles.button.secondary}`}
                >
                  Sign out
                </button>
              </div>
            </div>
          </header>

          <div className={componentStyles.layout.contentInner}>
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  )
}
