import { useState, useEffect } from 'react'
import { motion } from 'framer-motion'
import { 
  MonitorSmartphone, 
  Smartphone, 
  Laptop, 
  Server, 
  Router, 
  Printer,
  RefreshCw,
  Search,
  Filter,
  MoreVertical,
  Wifi,
  WifiOff
} from 'lucide-react'
import { componentStyles, typography } from '../styles/designSystem'
import api from '../services/api'

export default function DevicesPage() {
  const [devices, setDevices] = useState([])
  const [loading, setLoading] = useState(true)
  const [searchTerm, setSearchTerm] = useState('')
  const [filterStatus, setFilterStatus] = useState('all')
  const [stats, setStats] = useState({
    total: 0,
    online: 0,
    offline: 0,
    warning: 0
  })

  useEffect(() => {
    fetchDevices()
    // Auto-refresh every 30 seconds
    const interval = setInterval(fetchDevices, 30000)
    return () => clearInterval(interval)
  }, [])

  const fetchDevices = async () => {
    try {
      setLoading(true)
      const response = await api.get('/api/devices')
      const deviceData = response.data?.devices || []
      
      setDevices(deviceData)
      
      // Calculate stats
      const total = deviceData.length
      const online = deviceData.filter(d => d.status === 'online').length
      const offline = deviceData.filter(d => d.status === 'offline').length
      const warning = deviceData.filter(d => d.status === 'warning').length
      
      setStats({ total, online, offline, warning })
      
    } catch (error) {
      console.error('Failed to fetch devices:', error)
    } finally {
      setLoading(false)
    }
  }

  const getDeviceIcon = (type) => {
    switch (type?.toLowerCase()) {
      case 'desktop':
      case 'laptop':
        return Laptop
      case 'mobile':
      case 'smartphone':
        return Smartphone
      case 'server':
        return Server
      case 'router':
      case 'switch':
        return Router
      case 'printer':
        return Printer
      default:
        return MonitorSmartphone
    }
  }

  const getStatusColor = (status) => {
    switch (status?.toLowerCase()) {
      case 'online':
        return 'text-green-600 bg-green-100'
      case 'offline':
        return 'text-red-600 bg-red-100'
      case 'warning':
        return 'text-yellow-600 bg-yellow-100'
      default:
        return 'text-gray-600 bg-gray-100'
    }
  }

  const getRiskColor = (level) => {
    switch (level?.toLowerCase()) {
      case 'high':
        return 'text-red-600 bg-red-100 border-red-200'
      case 'medium':
        return 'text-yellow-600 bg-yellow-100 border-yellow-200'
      case 'low':
        return 'text-green-600 bg-green-100 border-green-200'
      default:
        return 'text-gray-600 bg-gray-100 border-gray-200'
    }
  }

  const formatTimeAgo = (timestamp) => {
    if (!timestamp) return 'Never'
    const now = new Date()
    const time = new Date(timestamp)
    const diffMs = now - time
    const diffMins = Math.floor(diffMs / 60000)
    
    if (diffMins < 1) return 'Just now'
    if (diffMins < 60) return `${diffMins}m ago`
    if (diffMins < 1440) return `${Math.floor(diffMins / 60)}h ago`
    return `${Math.floor(diffMins / 1440)}d ago`
  }

  const filteredDevices = devices.filter(device => {
    const matchesSearch = device.name?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         device.ip?.includes(searchTerm) ||
                         device.mac?.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         device.type?.toLowerCase().includes(searchTerm.toLowerCase())
    
    const matchesFilter = filterStatus === 'all' || device.status === filterStatus
    
    return matchesSearch && matchesFilter
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
          <h1 className={typography.h1}>Network Devices</h1>
          <p className={typography.small}>Monitor and manage devices on your network</p>
        </div>
        <button
          onClick={fetchDevices}
          disabled={loading}
          className={`${componentStyles.button.base} ${componentStyles.button.primary} flex items-center gap-2`}
        >
          <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-6">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          className={componentStyles.card}
        >
          <div className="flex items-center justify-between">
            <div>
              <p className={typography.small}>Total Devices</p>
              <p className={typography.h3}>{stats.total}</p>
            </div>
            <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.primary}`}>
              <MonitorSmartphone className="w-6 h-6" />
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
              <p className={typography.small}>Online</p>
              <p className={typography.h3}>{stats.online}</p>
            </div>
            <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.success}`}>
              <Wifi className="w-6 h-6" />
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
              <p className={typography.small}>Offline</p>
              <p className={typography.h3}>{stats.offline}</p>
            </div>
            <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.neutral}`}>
              <WifiOff className="w-6 h-6" />
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className={componentStyles.card}
        >
          <div className="flex items-center justify-between">
            <div>
              <p className={typography.small}>Warnings</p>
              <p className={typography.h3}>{stats.warning}</p>
            </div>
            <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.accent}`}>
              <MonitorSmartphone className="w-6 h-6" />
            </div>
          </div>
        </motion.div>
      </div>

      {/* Filters and Search */}
      <div className={componentStyles.card}>
        <div className="flex flex-col sm:flex-row gap-4">
          <div className="flex-1 relative">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-gray-400" />
            <input
              type="text"
              placeholder="Search devices by name, IP, MAC, or type..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            />
          </div>
          
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-gray-500" />
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              className="border border-gray-300 rounded-lg px-3 py-2 bg-white text-sm"
            >
              <option value="all">All Status</option>
              <option value="online">Online</option>
              <option value="offline">Offline</option>
              <option value="warning">Warning</option>
            </select>
          </div>
        </div>
      </div>

      {/* Devices List */}
      <div className={componentStyles.card}>
        <div className="mb-6">
          <h2 className={typography.h3}>Discovered Devices</h2>
          <p className={typography.small}>
            Showing {filteredDevices.length} of {devices.length} devices
          </p>
        </div>

        {filteredDevices.length === 0 ? (
          <div className="text-center py-12 text-gray-500">
            <MonitorSmartphone className="w-12 h-12 mx-auto mb-4 opacity-50" />
            <p className="text-lg font-medium mb-2">No devices found</p>
            <p className="text-sm">
              {devices.length === 0 
                ? "No devices discovered on the network" 
                : "No devices match your search criteria"
              }
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {filteredDevices.map((device, index) => {
              const DeviceIcon = getDeviceIcon(device.type)
              
              return (
                <motion.div
                  key={device.id || index}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: index * 0.05 }}
                  className="p-4 border border-gray-200 rounded-lg hover:border-gray-300 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex items-start gap-3 flex-1">
                      <div className={`${componentStyles.statIcon.base} ${componentStyles.statIcon.neutral} flex-shrink-0`}>
                        <DeviceIcon className="w-5 h-5" />
                      </div>
                      
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <h3 className="font-semibold text-gray-900 truncate">
                            {device.name || 'Unknown Device'}
                          </h3>
                          <span className={`px-2 py-1 rounded-full text-xs font-medium ${getStatusColor(device.status)}`}>
                            {device.status || 'unknown'}
                          </span>
                        </div>
                        
                        <div className="space-y-1 text-sm text-gray-600">
                          <p>IP: <span className="font-mono">{device.ip || 'N/A'}</span></p>
                          <p>MAC: <span className="font-mono">{device.mac || 'N/A'}</span></p>
                          <p>Type: {device.type || 'Unknown'}</p>
                          <p>OS: {device.os || 'Unknown'}</p>
                        </div>

                        <div className="flex items-center gap-4 mt-3">
                          <span className={`px-2 py-1 rounded text-xs font-medium border ${getRiskColor(device.risk_level)}`}>
                            {(device.risk_level || 'unknown').toUpperCase()} RISK
                          </span>
                          
                          <span className={typography.caption}>
                            Last seen: {formatTimeAgo(device.last_seen)}
                          </span>
                        </div>
                      </div>
                    </div>
                    
                    <button className="p-1 text-gray-400 hover:text-gray-600">
                      <MoreVertical className="w-4 h-4" />
                    </button>
                  </div>
                </motion.div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}