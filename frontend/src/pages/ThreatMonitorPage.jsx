import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import { 
  Activity, 
  Filter, 
  RefreshCcw, 
  PlayCircle, 
  PauseCircle, 
  AlertTriangle, 
  Shield, 
  Clock,
  MapPin,
  Eye,
  Download
} from 'lucide-react'
import toast from 'react-hot-toast'
import { componentStyles, typography } from '../styles/designSystem'
import api from '../services/api'

export default function ThreatMonitorPage() {
  const [threats, setThreats] = useState([])
  const [loading, setLoading] = useState(true)
  const [streaming, setStreaming] = useState(false)
  const [filters, setFilters] = useState({
    severity: 'all',
    status: 'all',
    source: 'all'
  })
  const [stats, setStats] = useState({
    total: 0,
    active: 0,
    resolved: 0
  })
  const streamInterval = useRef(null)

  useEffect(() => {
    fetchThreats(true)
    
    // Start automatic refresh every 10 seconds
    const interval = setInterval(() => {
      if (!streaming) {
        fetchThreats(false)
      }
    }, 10000)

    return () => {
      clearInterval(interval)
      if (streamInterval.current) {
        clearInterval(streamInterval.current)
      }
    }
  }, [streaming])

  const fetchThreats = async (showLoading = false) => {
    try {
      if (showLoading) setLoading(true)
      
      const response = await api.get('/api/threats/recent?limit=50')
      const threatData = response.data?.threats || []
      
      setThreats(threatData)
      
      // Calculate stats
      const totalThreats = threatData.length
      const activeThreats = threatData.filter(t => t.status === 'active').length
      const resolvedThreats = threatData.filter(t => t.status === 'resolved').length
      
      setStats({
        total: totalThreats,
        active: activeThreats,
        resolved: resolvedThreats
      })
      
    } catch (error) {
      console.error('Failed to fetch threats:', error)
      if (showLoading) {
        toast.error('Failed to fetch threat data')
      }
    } finally {
      if (showLoading) setLoading(false)
    }
  }

  const toggleStreaming = () => {
    if (streaming) {
      clearInterval(streamInterval.current)
      setStreaming(false)
      toast.success('Live streaming paused')
    } else {
      streamInterval.current = setInterval(() => {
        fetchThreats(false)
      }, 2000) // Update every 2 seconds when streaming
      setStreaming(true)
      toast.success('Live streaming enabled')
    }
  }

  const handleExport = async () => {
    try {
      const response = await api.get('/api/threats/recent?limit=1000')
      const data = response.data?.threats || []
      
      const blob = new Blob([JSON.stringify(data, null, 2)], {
        type: 'application/json'
      })
      
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `threat-events-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(link)
      link.click()
      document.body.removeChild(link)
      URL.revokeObjectURL(url)
      
      toast.success('Threat data exported successfully')
    } catch (error) {
      toast.error('Failed to export threat data')
    }
  }

  const getSeverityColor = (severity) => {
    switch (severity?.toLowerCase()) {
      case 'critical':
        return 'bg-red-100 text-red-700 border-red-200'
      case 'high':
        return 'bg-red-100 text-red-700 border-red-200'
      case 'medium':
        return 'bg-yellow-100 text-yellow-700 border-yellow-200'
      case 'low':
        return 'bg-green-100 text-green-700 border-green-200'
      default:
        return 'bg-gray-100 text-gray-700 border-gray-200'
    }
  }

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'active':
        return 'bg-red-100 text-red-700'
      case 'investigating':
        return 'bg-blue-100 text-blue-700'
      case 'resolved':
        return 'bg-green-100 text-green-700'
      default:
        return 'bg-gray-100 text-gray-700'
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

  const filteredThreats = threats.filter(threat => {
    if (filters.severity !== 'all' && threat.severity !== filters.severity) return false
    if (filters.status !== 'all' && threat.status !== filters.status) return false
    if (filters.source !== 'all' && threat.source !== filters.source) return false
    return true
  })

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600"></div>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className={typography.h1}>Threat Monitor</h1>
          <p className={typography.small}>Real-time threat detection and analysis</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={() => fetchThreats(true)}
            disabled={loading}
            className={`${componentStyles.button.base} ${componentStyles.button.secondary} flex items-center gap-2`}
          >
            <RefreshCcw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            Refresh
          </button>
          <button
            onClick={toggleStreaming}
            className={`${componentStyles.button.base} ${streaming ? componentStyles.button.danger : componentStyles.button.primary} flex items-center gap-2`}
          >
            {streaming ? <PauseCircle className="w-4 h-4" /> : <PlayCircle className="w-4 h-4" />}
            {streaming ? 'Stop Stream' : 'Live Stream'}
          </button>
          <button
            onClick={handleExport}
            className={`${componentStyles.button.base} ${componentStyles.button.secondary} flex items-center gap-2`}
          >
            <Download className="w-4 h-4" />
            Export
          </button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className={componentStyles.card}
        >
          <div className="flex items-center justify-between">
            <div>
              <p className={typography.small}>Total Threats</p>
              <p className={typography.h3}>{stats.total}</p>
            </div>
            <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.primary}`}>
              <AlertTriangle className="w-6 h-6" />
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.1 }}
          className={componentStyles.card}
        >
          <div className="flex items-center justify-between">
            <div>
              <p className={typography.small}>Active Threats</p>
              <p className={typography.h3}>{stats.active}</p>
            </div>
            <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.accent}`}>
              <Eye className="w-6 h-6" />
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
          className={componentStyles.card}
        >
          <div className="flex items-center justify-between">
            <div>
              <p className={typography.small}>Resolved</p>
              <p className={typography.h3}>{stats.resolved}</p>
            </div>
            <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.success}`}>
              <Shield className="w-6 h-6" />
            </div>
          </div>
        </motion.div>
      </div>

      {/* Filters */}
      <div className={componentStyles.card}>
        <div className="flex items-center gap-4 flex-wrap">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-gray-500" />
            <span className="text-sm font-medium text-gray-700">Filters:</span>
          </div>
          
          <select
            value={filters.severity}
            onChange={(e) => setFilters({ ...filters, severity: e.target.value })}
            className="text-sm border border-gray-300 rounded-lg px-3 py-1 bg-white"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <select
            value={filters.status}
            onChange={(e) => setFilters({ ...filters, status: e.target.value })}
            className="text-sm border border-gray-300 rounded-lg px-3 py-1 bg-white"
          >
            <option value="all">All Status</option>
            <option value="active">Active</option>
            <option value="investigating">Investigating</option>
            <option value="resolved">Resolved</option>
          </select>

          <select
            value={filters.source}
            onChange={(e) => setFilters({ ...filters, source: e.target.value })}
            className="text-sm border border-gray-300 rounded-lg px-3 py-1 bg-white"
          >
            <option value="all">All Sources</option>
            <option value="network">Network</option>
            <option value="system">System</option>
            <option value="endpoint">Endpoint</option>
          </select>

          {streaming && (
            <div className="flex items-center gap-2 text-green-600 text-sm">
              <div className="w-2 h-2 bg-green-500 rounded-full animate-pulse"></div>
              Live
            </div>
          )}
        </div>
      </div>

      {/* Threats List */}
      <div className={componentStyles.card}>
        <div className="mb-6">
          <h2 className={typography.h3}>Threat Events</h2>
          <p className={typography.small}>
            Showing {filteredThreats.length} of {threats.length} threats
          </p>
        </div>

        {filteredThreats.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <AlertTriangle className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <p className="text-lg font-medium mb-2">No threats found</p>
            <p className="text-sm">
              {threats.length === 0 
                ? "No threat events detected yet" 
                : "No threats match your current filters"
              }
            </p>
          </div>
        ) : (
          <div className="space-y-4">
            {filteredThreats.map((threat, index) => (
              <motion.div
                key={threat.id || index}
                initial={{ opacity: 0, y: 20 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: index * 0.05 }}
                className="p-4 border border-gray-200 rounded-lg hover:border-gray-300 transition-colors"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2">
                      <h3 className="font-semibold text-gray-900">
                        {threat.type || 'Unknown Threat'}
                      </h3>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium border ${getSeverityColor(threat.severity)}`}>
                        {(threat.severity || 'unknown').toUpperCase()}
                      </span>
                      <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(threat.status)}`}>
                        {(threat.status || 'unknown').toUpperCase()}
                      </span>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 text-sm text-gray-600">
                      <div className="flex items-center gap-2">
                        <Activity className="w-4 h-4" />
                        <span>Source: {threat.source || 'Unknown'}</span>
                      </div>
                      
                      <div className="flex items-center gap-2">
                        <Clock className="w-4 h-4" />
                        <span>{formatTimeAgo(threat.timestamp)}</span>
                      </div>
                      
                      {threat.threat_score && (
                        <div className="flex items-center gap-2">
                          <Shield className="w-4 h-4" />
                          <span>Risk Score: {(threat.threat_score * 100).toFixed(0)}%</span>
                        </div>
                      )}
                    </div>

                    {threat.summary && (
                      <div className="mt-3 text-sm text-gray-700">
                        <p>{JSON.stringify(threat.summary)}</p>
                      </div>
                    )}

                    {threat.indicators && threat.indicators.length > 0 && (
                      <div className="mt-3">
                        <div className="flex flex-wrap gap-1">
                          {threat.indicators.slice(0, 5).map((indicator, idx) => (
                            <span
                              key={idx}
                              className="px-2 py-1 bg-gray-100 text-gray-700 text-xs rounded"
                            >
                              {indicator}
                            </span>
                          ))}
                          {threat.indicators.length > 5 && (
                            <span className="px-2 py-1 bg-gray-100 text-gray-500 text-xs rounded">
                              +{threat.indicators.length - 5} more
                            </span>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              </motion.div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}