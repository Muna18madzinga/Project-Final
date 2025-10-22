import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import {
  AlertTriangle,
  BellRing,
  CheckCircle2,
  Cpu,
  Database,
  Gauge,
  Inbox,
  ServerCog,
  TrendingUp,
  Users
} from 'lucide-react'
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, Legend } from 'recharts'
import api from '../services/api'
import { componentStyles, typography, colors } from '../styles/designSystem'

export default function DashboardPage() {
  const [stats, setStats] = useState({
    totalThreats: 0,
    blockedThreats: 0,
    activeSessions: 0,
    riskScore: 0
  })
  const [alertTimeline, setAlertTimeline] = useState([])
  const [trafficData, setTrafficData] = useState([])
  const [recentAlerts, setRecentAlerts] = useState([])
  const [alertDistribution, setAlertDistribution] = useState([])
  const [loading, setLoading] = useState(true)
  const [exporting, setExporting] = useState(false)

  useEffect(() => {
    fetchDashboardData()
    const interval = setInterval(fetchDashboardData, 10000) // Refresh every 10 seconds
    return () => clearInterval(interval)
  }, [])

  const formatTimeAgo = (timestamp) => {
    try {
      const date = new Date(timestamp)
      const seconds = Math.floor((new Date() - date) / 1000)

      if (seconds < 60) return `${seconds} seconds ago`
      if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`
      if (seconds < 86400) return `${Math.floor(seconds / 3600)} hours ago`
      return `${Math.floor(seconds / 86400)} days ago`
    } catch {
      return timestamp
    }
  }

  const getSeverityStyles = (severity) => {
    const key = (severity || 'low').toLowerCase()
    return componentStyles.severity[key] || componentStyles.severity.low
  }

  const fetchDashboardData = async () => {
    try {
      const responses = await Promise.allSettled([
        api.get('/api/suite/status'),
        api.get('/api/threats/timeline'),
        api.get('/api/network/traffic'),
        api.get('/api/metrics/live'),
        api.get('/api/threats/recent?limit=12')
      ])

      const [suiteStatus, threatTimeline, networkTraffic, liveMetrics, threats] = responses

      setStats({
        totalThreats: suiteStatus.value?.data?.metrics?.total_threats_detected || 0,
        blockedThreats: suiteStatus.value?.data?.metrics?.total_policies_enforced || 0,
        activeSessions: liveMetrics.value?.data?.active_sessions || 0,
        riskScore: Math.min(
          100,
          Math.max(0, 100 - (suiteStatus.value?.data?.metrics?.total_threats_detected || 0) * 2)
        )
      })

      const timeline = (threatTimeline.value?.data || []).map((entry) => ({
        time: entry.time || entry.hour || entry.label,
        alerts: entry.threats ?? entry.alerts ?? 0,
        resolved: entry.blocked ?? entry.resolved ?? 0
      }))
      setAlertTimeline(timeline)

      const traffic = networkTraffic.value?.data || {}
      const timestamp = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
      const incoming = Math.max(0, Math.round((traffic.bytes_recv_per_sec ?? 0) / 1024))
      const outgoing = Math.max(0, Math.round((traffic.bytes_sent_per_sec ?? 0) / 1024))

      setTrafficData((prev) => [...prev.slice(-23), { time: timestamp, incoming, outgoing }])

      const recent = threats.value?.data || []
      setRecentAlerts(recent.slice(0, 6))

      if (recent.length) {
        const severityCounts = recent.reduce(
          (acc, alert) => {
            const level = (alert.severity || 'low').toLowerCase()
            acc[level] = (acc[level] || 0) + 1
            return acc
          },
          { high: 0, medium: 0, low: 0 }
        )
        const total = Object.values(severityCounts).reduce((sum, val) => sum + val, 0) || 1
        setAlertDistribution([
          { name: 'High severity', value: Math.round((severityCounts.high / total) * 100), color: colors.error },
          { name: 'Medium', value: Math.round((severityCounts.medium / total) * 100), color: colors.warning },
          { name: 'Low', value: Math.round((severityCounts.low / total) * 100), color: colors.success }
        ])
      } else {
        setAlertDistribution([
          { name: 'High severity', value: 10, color: colors.error },
          { name: 'Medium', value: 30, color: colors.warning },
          { name: 'Low', value: 60, color: colors.success }
        ])
      }

      setLoading(false)
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error)
      setLoading(false)
    }
  }

  const handleExportHistory = async () => {
    try {
      setExporting(true)
      const response = await api.get('/api/alerts/history?limit=100')
      const alerts = response.data?.alerts || []
      const blob = new Blob([JSON.stringify(alerts, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `alert-history-${Date.now()}.json`
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to export alert history:', error)
    } finally {
      setExporting(false)
    }
  }

  const StatCard = ({ icon: Icon, title, value, change, variant = 'primary', isLoading }) => (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ scale: 1.02 }}
      transition={{ duration: 0.2 }}
      className={componentStyles.card}
    >
      <div className="flex items-center justify-between">
        <div>
          <p className={typography.small + ' mb-1'}>{title}</p>
          {isLoading ? (
            <div className="h-8 w-24 bg-gray-200 animate-pulse rounded" />
          ) : (
            <h3 className="text-3xl font-bold text-gray-900">{value}</h3>
          )}
          {change && (
            <p className={typography.small + ' text-emerald-600 mt-1 flex items-center gap-1'}>
              <TrendingUp className="w-4 h-4" />
              {change}
            </p>
          )}
        </div>
        <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon[variant]}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </motion.div>
  )

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <h1 className={typography.h1}>Operations Overview</h1>
        <p className={typography.small + ' mt-1'}>Real-time system insights and alert tracking</p>
      </div>

      {/* Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          icon={BellRing}
          title="Total Alerts"
          value={stats.totalThreats}
          change="+12% vs last week"
          variant="primary"
          isLoading={loading}
        />
        <StatCard
          icon={CheckCircle2}
          title="Resolved Alerts"
          value={stats.blockedThreats}
          change="+8% efficiency"
          variant="success"
          isLoading={loading}
        />
        <StatCard
          icon={Users}
          title="Active Sessions"
          value={stats.activeSessions}
          variant="accent"
          isLoading={loading}
        />
        <StatCard
          icon={Gauge}
          title="Stability Score"
          value={`${stats.riskScore}%`}
          change="Consistent"
          variant="neutral"
          isLoading={loading}
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Alert Timeline */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className={componentStyles.card}
        >
          <div className="flex items-center justify-between mb-6">
            <div>
              <h2 className={typography.h3}>Alert Activity</h2>
              <p className={typography.small}>Last 24 hours</p>
            </div>
            <div className="flex gap-4 text-sm">
              <div className="flex items-center gap-2">
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: colors.error }}
                />
                <span>Alerts</span>
              </div>
              <div className="flex items-center gap-2">
                <div
                  className="w-3 h-3 rounded-full"
                  style={{ backgroundColor: colors.success }}
                />
                <span>Resolved</span>
              </div>
            </div>
          </div>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={alertTimeline}>
              <defs>
                <linearGradient id="colorAlerts" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={colors.error} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={colors.error} stopOpacity={0} />
                </linearGradient>
                <linearGradient id="colorResolved" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={colors.success} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={colors.success} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="time" stroke="#9ca3af" />
              <YAxis stroke="#9ca3af" />
              <Tooltip
                contentStyle={{
                  backgroundColor: '#ffffff',
                  border: '1px solid #e5e7eb',
                  borderRadius: '0.5rem'
                }}
                formatter={(value, name) => [
                  value,
                  name === 'alerts' ? 'Alerts' : 'Resolved'
                ]}
                labelFormatter={(label) => `Hour ${label}`}
              />
              <Area
                type="monotone"
                dataKey="alerts"
                stroke={colors.error}
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorAlerts)"
                name="Alerts"
              />
              <Area
                type="monotone"
                dataKey="resolved"
                stroke={colors.success}
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#colorResolved)"
                name="Resolved"
              />
            </AreaChart>
          </ResponsiveContainer>
        </motion.div>

        {/* Alert Distribution */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className={componentStyles.card}
        >
          <div className="mb-6">
            <h2 className={typography.h3}>Alert Distribution</h2>
            <p className={typography.small}>By category</p>
          </div>
          <div className="flex items-center justify-between">
            <ResponsiveContainer width="50%" height={200}>
              <PieChart>
                <Pie
                  data={alertDistribution}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={80}
                  paddingAngle={5}
                  dataKey="value"
                >
                  {alertDistribution.map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={entry.color} />
                  ))}
                </Pie>
              </PieChart>
            </ResponsiveContainer>
            <div className="space-y-3">
              {alertDistribution.map((item, index) => (
                <div key={index} className="flex items-center gap-3">
                  <div
                    className="w-3 h-3 rounded-full"
                    style={{ backgroundColor: item.color }}
                  />
                  <span className="text-sm text-gray-700 flex-1">{item.name}</span>
                  <span className="text-sm font-semibold text-gray-900">{item.value}%</span>
                </div>
              ))}
            </div>
          </div>
        </motion.div>
      </div>

      {/* Network Traffic Chart */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className={componentStyles.card}
      >
        <div className="mb-6">
          <h2 className={typography.h3}>Network Traffic Volume</h2>
          <p className={typography.small}>Real-time incoming and outgoing traffic (KB/s)</p>
        </div>
        <ResponsiveContainer width="100%" height={250}>
          <LineChart data={trafficData}>
            <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
            <XAxis dataKey="time" stroke="#9ca3af" />
            <YAxis stroke="#9ca3af" />
            <Tooltip
              contentStyle={{
                backgroundColor: '#ffffff',
                border: '1px solid #e5e7eb',
                borderRadius: '0.5rem'
              }}
              formatter={(value, name) => [`${value} KB/s`, name]}
            />
            <Legend />
            <Line
              type="monotone"
              dataKey="incoming"
              stroke={colors.primary[500]}
              strokeWidth={2}
              name="Incoming"
            />
            <Line
              type="monotone"
              dataKey="outgoing"
              stroke={colors.primary[700]}
              strokeWidth={2}
              name="Outgoing"
            />
          </LineChart>
        </ResponsiveContainer>
      </motion.div>

      {/* Recent Alerts */}
      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.3 }}
        className={componentStyles.card}
      >
        <div className="flex items-center justify-between mb-6">
          <div>
            <h2 className={typography.h3}>Recent Alerts</h2>
            <p className={typography.small}>Latest events from the monitoring service</p>
          </div>
          <button
            onClick={handleExportHistory}
            disabled={exporting}
            className={`${componentStyles.button.base} ${componentStyles.button.secondary} text-sm`}
          >
            View history
          </button>
        </div>
        <div className="space-y-4">
          {recentAlerts.length === 0 ? (
            <div className="text-center py-8 text-gray-500">
              <Inbox className="w-12 h-12 mx-auto mb-2 opacity-50" />
              <p>No recent alerts</p>
              <p className="text-sm">Everything looks calm right now</p>
            </div>
          ) : (
            recentAlerts.map((alert, index) => {
              const severityStyles = getSeverityStyles(alert.severity)
              const status = (alert.status || 'monitoring').replace('_', ' ')

              return (
                <div
                  key={index}
                  className="flex items-center justify-between p-4 rounded-xl border border-gray-100 hover:border-gray-200 transition-colors"
                >
                  <div className="flex items-center gap-4">
                  <div className={`p-3 rounded-lg border ${severityStyles.border} ${severityStyles.bg}`}>
                      <AlertTriangle className={`w-5 h-5 ${severityStyles.icon}`} />
                    </div>
                    <div>
                      <p className="font-semibold text-gray-900">{alert.type}</p>
                      <p className="text-sm text-gray-600">
                        {alert.ip} - {formatTimeAgo(alert.time)}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-3">
                    <span
                      className={`${componentStyles.badge.base} ${
                        status.toLowerCase() === 'blocked'
                          ? componentStyles.badge.success
                          : componentStyles.badge.info
                      }`}
                    >
                      {status}
                    </span>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </motion.div>

      {/* System Status */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {[
          { label: 'Processing Nodes', value: 'Online', icon: ServerCog, color: 'text-emerald-600' },
          { label: 'Data Pipeline', value: 'Stable', icon: Database, color: 'text-blue-600' },
          { label: 'Compute Usage', value: '64%', icon: Cpu, color: 'text-indigo-600' }
        ].map((item, index) => (
          <motion.div
            key={index}
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.4 + index * 0.1 }}
            className="bg-white rounded-xl p-4 shadow border border-gray-100 flex items-center gap-4"
          >
            <item.icon className={`w-6 h-6 ${item.color}`} />
            <div>
              <p className="text-sm text-gray-600">{item.label}</p>
              <p className="font-semibold text-gray-900">{item.value}</p>
            </div>
          </motion.div>
        ))}
      </div>
    </div>
  )
}
