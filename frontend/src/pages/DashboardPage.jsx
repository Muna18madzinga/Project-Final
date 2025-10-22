import { useState, useEffect } from 'react'
import { Activity, Shield, AlertTriangle, Network, Server, Eye, Cpu, Database, Users, TrendingUp } from 'lucide-react'
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts'
import { componentStyles, typography, colors } from '../styles/designSystem'
import api from '../services/api'

export default function DashboardPage() {
  const [stats, setStats] = useState(null)
  const [systemMetrics, setSystemMetrics] = useState(null)
  const [threatData, setThreatData] = useState([])
  const [networkEvents, setNetworkEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [lastUpdate, setLastUpdate] = useState(null)

  useEffect(() => {
    fetchDashboardData()
    const interval = setInterval(fetchDashboardData, 5000) // Update every 5 seconds
    return () => clearInterval(interval)
  }, [])

  const fetchDashboardData = async () => {
    try {
      const responses = await Promise.allSettled([
        api.get('/api/dashboard/stats'),
        api.get('/api/system/metrics'),
        api.get('/api/threats/recent?limit=10'),
        api.get('/api/network/events?limit=20')
      ])

      const [statsRes, metricsRes, threatsRes, eventsRes] = responses

      if (statsRes.status === 'fulfilled') {
        setStats(statsRes.value.data)
        setLastUpdate(new Date())
      }

      if (metricsRes.status === 'fulfilled') {
        setSystemMetrics(metricsRes.value.data)
      }

      if (threatsRes.status === 'fulfilled') {
        const threats = threatsRes.value.data.threats || []
        setThreatData(threats.map((threat, index) => ({
          time: new Date(threat.timestamp).getHours() + ':' + String(new Date(threat.timestamp).getMinutes()).padStart(2, '0'),
          threats: index + 1,
          severity: threat.severity,
          score: threat.threat_score || 0
        })))
      }

      if (eventsRes.status === 'fulfilled') {
        setNetworkEvents(eventsRes.value.data.events || [])
      }

      setError(null)
    } catch (err) {
      console.error('Dashboard data fetch error:', err)
      setError('Failed to fetch dashboard data')
    } finally {
      setLoading(false)
    }
  }

  const formatTimeAgo = (timestamp) => {
    if (!timestamp) return 'Unknown'
    const now = new Date()
    const time = new Date(timestamp)
    const diffMs = now - time
    const diffMins = Math.floor(diffMs / 60000)
    
    if (diffMins < 1) return 'Just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`
    return `${Math.floor(diffMins / 1440)}d ago`
  }

  const StatCard = ({ icon: Icon, title, value, subtitle, color = 'primary', trend, loading: cardLoading }) => (
    <div className={componentStyles.card}>
      <div className="flex items-center justify-between">
        <div className="flex-1">
          <p className={typography.small}>{title}</p>
          {cardLoading ? (
            <div className="h-8 w-24 bg-gray-200 animate-pulse rounded mt-1" />
          ) : (
            <p className={typography.h3}>{value}</p>
          )}
          <div className="flex items-center gap-2 mt-1">
            <p className={typography.caption}>{subtitle}</p>
            {trend && (
              <span className="flex items-center gap-1 text-green-600 text-xs">
                <TrendingUp className="w-3 h-3" />
                {trend}
              </span>
            )}
          </div>
        </div>
        <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon[color]}`}>
          <Icon className="w-6 h-6" />
        </div>
      </div>
    </div>
  )

  if (error) {
    return (
      <div className="space-y-6">
        <div className={`${componentStyles.card} bg-red-50 border-red-200`}>
          <div className="flex items-center gap-3 text-red-700">
            <AlertTriangle className="w-5 h-5" />
            <div>
              <p className="font-medium">Error Loading Dashboard</p>
              <p className="text-sm">{error}</p>
            </div>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={typography.h1}>Security Dashboard</h1>
          <p className={typography.small}>
            Real-time monitoring and threat detection overview
          </p>
        </div>
        <div className="text-right">
          <div className={`inline-flex items-center gap-2 px-3 py-1 rounded-full text-xs ${
            stats?.real_data_available 
              ? 'bg-green-100 text-green-700' 
              : 'bg-yellow-100 text-yellow-700'
          }`}>
            <div className={`w-2 h-2 rounded-full ${
              stats?.real_data_available ? 'bg-green-500' : 'bg-yellow-500'
            }`} />
            {stats?.real_data_available ? 'Live Data' : 'Demo Mode'}
          </div>
          {lastUpdate && (
            <p className={typography.caption + ' mt-1'}>
              Updated {formatTimeAgo(lastUpdate)}
            </p>
          )}
        </div>
      </div>

      {/* Main Stats Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <StatCard
          icon={Network}
          title="Network Packets"
          value={stats?.network?.packets_captured?.toLocaleString() || '0'}
          subtitle={`${stats?.network?.packets_per_second?.toFixed(1) || '0'} pps`}
          color="primary"
          loading={loading}
          trend="+12%"
        />
        <StatCard
          icon={Shield}
          title="Threat Indicators"
          value={stats?.threats?.total_indicators?.toLocaleString() || '0'}
          subtitle={`${stats?.threats?.threat_matches || 0} active matches`}
          color="accent"
          loading={loading}
        />
        <StatCard
          icon={AlertTriangle}
          title="High Risk Events"
          value={stats?.threats?.high_risk_events?.toString() || '0'}
          subtitle="Requires attention"
          color="success"
          loading={loading}
        />
        <StatCard
          icon={Activity}
          title="Events Processed"
          value={stats?.telemetry?.events_processed?.toLocaleString() || '0'}
          subtitle={`${stats?.telemetry?.threat_events || 0} threat events`}
          color="neutral"
          loading={loading}
        />
      </div>

      {/* System Health Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className={componentStyles.card}>
          <div className="flex items-center gap-4">
            <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.primary}`}>
              <Cpu className="w-6 h-6" />
            </div>
            <div className="flex-1">
              <p className={typography.small}>CPU Usage</p>
              <p className={typography.h4}>
                {systemMetrics?.cpu_percent?.toFixed(1) || '0'}%
              </p>
              <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                <div 
                  className="bg-blue-600 h-2 rounded-full transition-all duration-300" 
                  style={{ width: `${Math.min(100, systemMetrics?.cpu_percent || 0)}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        <div className={componentStyles.card}>
          <div className="flex items-center gap-4">
            <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.success}`}>
              <Database className="w-6 h-6" />
            </div>
            <div className="flex-1">
              <p className={typography.small}>Memory Usage</p>
              <p className={typography.h4}>
                {systemMetrics?.memory_percent?.toFixed(1) || '0'}%
              </p>
              <div className="w-full bg-gray-200 rounded-full h-2 mt-2">
                <div 
                  className="bg-green-600 h-2 rounded-full transition-all duration-300" 
                  style={{ width: `${Math.min(100, systemMetrics?.memory_percent || 0)}%` }}
                />
              </div>
            </div>
          </div>
        </div>

        <div className={componentStyles.card}>
          <div className="flex items-center gap-4">
            <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.neutral}`}>
              <Users className="w-6 h-6" />
            </div>
            <div className="flex-1">
              <p className={typography.small}>Active Connections</p>
              <p className={typography.h4}>
                {systemMetrics?.active_connections?.toLocaleString() || '0'}
              </p>
              <p className={typography.caption}>
                {systemMetrics?.processes_count || '0'} processes
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Threat Timeline */}
        <div className={componentStyles.card}>
          <div className="mb-6">
            <h3 className={typography.h3}>Threat Activity</h3>
            <p className={typography.small}>Recent threat detection timeline</p>
          </div>
          <ResponsiveContainer width="100%" height={250}>
            <AreaChart data={threatData}>
              <defs>
                <linearGradient id="threatGradient" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={colors.error} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={colors.error} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
              <XAxis dataKey="time" stroke="#9ca3af" fontSize={12} />
              <YAxis stroke="#9ca3af" fontSize={12} />
              <Tooltip
                contentStyle={{
                  backgroundColor: 'white',
                  border: '1px solid #e5e7eb',
                  borderRadius: '8px',
                  fontSize: '12px'
                }}
              />
              <Area
                type="monotone"
                dataKey="threats"
                stroke={colors.error}
                strokeWidth={2}
                fillOpacity={1}
                fill="url(#threatGradient)"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Network Traffic */}
        <div className={componentStyles.card}>
          <div className="mb-6">
            <h3 className={typography.h3}>Network Interface</h3>
            <p className={typography.small}>
              Interface: {stats?.network?.interface || 'Not detected'}
            </p>
          </div>
          <div className="space-y-4">
            <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div>
                <p className="font-medium">Data Transfer</p>
                <p className={typography.caption}>Bytes sent/received</p>
              </div>
              <div className="text-right">
                <p className="font-mono text-sm">
                  ↑ {((systemMetrics?.network_bytes_sent || 0) / 1024 / 1024).toFixed(1)}MB
                </p>
                <p className="font-mono text-sm">
                  ↓ {((systemMetrics?.network_bytes_recv || 0) / 1024 / 1024).toFixed(1)}MB
                </p>
              </div>
            </div>
            <div className="flex items-center justify-between p-4 bg-gray-50 rounded-lg">
              <div>
                <p className="font-medium">Active Flows</p>
                <p className={typography.caption}>Current connections</p>
              </div>
              <p className="text-2xl font-bold">
                {stats?.network?.active_flows || '0'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Recent Events Tables */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Recent Network Events */}
        <div className={componentStyles.card}>
          <div className="mb-6">
            <h3 className={typography.h3}>Recent Network Activity</h3>
            <p className={typography.small}>Latest network connections</p>
          </div>
          <div className="space-y-3">
            {networkEvents.length === 0 ? (
              <div className="text-center py-8 text-gray-500">
                <Network className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p>No recent network activity</p>
              </div>
            ) : (
              networkEvents.slice(0, 5).map((event, index) => (
                <div key={index} className="flex items-center justify-between p-3 rounded-lg border border-gray-100">
                  <div className="flex-1">
                    <p className="font-mono text-sm">
                      {event.source_ip}:{event.source_port} → {event.dest_ip}:{event.dest_port}
                    </p>
                    <p className={typography.caption}>
                      {event.protocol?.toUpperCase()} • {event.packet_size} bytes • {formatTimeAgo(event.timestamp)}
                    </p>
                  </div>
                  {event.threat_score > 0.5 && (
                    <div className={`${componentStyles.badge.base} ${componentStyles.badge.warning}`}>
                      Risk: {(event.threat_score * 100).toFixed(0)}%
                    </div>
                  )}
                </div>
              ))
            )}
          </div>
        </div>

        {/* System Status */}
        <div className={componentStyles.card}>
          <div className="mb-6">
            <h3 className={typography.h3}>System Status</h3>
            <p className={typography.small}>Component health overview</p>
          </div>
          <div className="space-y-4">
            {[
              {
                name: 'Network Monitoring',
                status: stats?.network?.interface ? 'online' : 'offline',
                details: stats?.network?.interface || 'No interface detected'
              },
              {
                name: 'Threat Intelligence',
                status: (stats?.threats?.total_indicators || 0) > 0 ? 'online' : 'offline',
                details: `${stats?.threats?.total_indicators || 0} indicators loaded`
              },
              {
                name: 'Telemetry Pipeline',
                status: (stats?.telemetry?.events_processed || 0) > 0 ? 'online' : 'offline',
                details: `${stats?.telemetry?.events_processed || 0} events processed`
              },
              {
                name: 'Real Data Collection',
                status: stats?.real_data_available ? 'online' : 'simulation',
                details: stats?.real_data_available ? 'Live data active' : 'Demo mode active'
              }
            ].map((component, index) => (
              <div key={index} className="flex items-center justify-between p-3 rounded-lg bg-gray-50">
                <div className="flex items-center gap-3">
                  <div className={`w-3 h-3 rounded-full ${
                    component.status === 'online' ? 'bg-green-400' :
                    component.status === 'simulation' ? 'bg-yellow-400' : 'bg-gray-400'
                  }`} />
                  <div>
                    <p className="font-medium text-sm">{component.name}</p>
                    <p className={typography.caption}>{component.details}</p>
                  </div>
                </div>
                <span className={`${componentStyles.badge.base} ${
                  component.status === 'online' ? componentStyles.badge.success :
                  component.status === 'simulation' ? componentStyles.badge.warning : componentStyles.badge.neutral
                }`}>
                  {component.status.toUpperCase()}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Data Mode Alert */}
      {!loading && stats && (
        <div className={`${componentStyles.card} ${
          stats.real_data_available 
            ? 'bg-green-50 border-green-200' 
            : 'bg-yellow-50 border-yellow-200'
        }`}>
          <div className="flex items-center gap-3">
            <Eye className={`w-5 h-5 ${
              stats.real_data_available ? 'text-green-600' : 'text-yellow-600'
            }`} />
            <div>
              <p className={`font-medium ${
                stats.real_data_available ? 'text-green-900' : 'text-yellow-900'
              }`}>
                {stats.real_data_available ? 'Live Data Collection Active' : 'Demo Mode Active'}
              </p>
              <p className={`text-sm ${
                stats.real_data_available ? 'text-green-700' : 'text-yellow-700'
              }`}>
                {stats.real_data_available 
                  ? 'System is collecting real network traffic and threat intelligence from live sources'
                  : 'System is running with simulated data for demonstration purposes. Install real data components for live monitoring.'
                }
              </p>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}