import { useEffect, useRef, useState } from 'react'
import { motion } from 'framer-motion'
import { Activity, Filter, RefreshCcw, PlayCircle, PauseCircle } from 'lucide-react'
import toast from 'react-hot-toast'
import PageShell from '../components/PageShell'
import { componentStyles, typography } from '../styles/designSystem'
import api from '../services/api'

export default function ThreatMonitorPage() {
  const [events, setEvents] = useState([])
  const [loading, setLoading] = useState(true)
  const [streaming, setStreaming] = useState(false)
  const [exporting, setExporting] = useState(false)
  const streamInterval = useRef(null)

  const fetchEvents = async (showIndicator = false) => {
    try {
      if (showIndicator) {
        setLoading(true)
      }
      const response = await api.get('/api/alerts/history?limit=40')
      setEvents(response.data?.alerts || [])
    } catch (error) {
      toast.error('Failed to fetch live events.')
      console.error('Failed to fetch events', error)
    } finally {
      if (showIndicator) {
        setLoading(false)
      }
    }
  }

  useEffect(() => {
    fetchEvents(true)
    return () => {
      if (streamInterval.current) {
        clearInterval(streamInterval.current)
      }
    }
  }, [])

  const toggleStreaming = async () => {
    if (streaming) {
      if (streamInterval.current) {
        clearInterval(streamInterval.current)
      }
      setStreaming(false)
      toast.success('Live stream paused')
      return
    }

    try {
      await api.post('/api/threat/simulate', { severity: 'medium' })
    } catch (error) {
      console.error('Failed to simulate threat', error)
    }

    await fetchEvents(true)
    streamInterval.current = setInterval(async () => {
      await api.post('/api/threat/simulate', { severity: 'low' }).catch(() => {})
      fetchEvents(false)
    }, 5000)

    setStreaming(true)
    toast.success('Live stream started')
  }

  const handleRefresh = async () => {
    await fetchEvents(true)
    toast.success('Live events refreshed')
  }

  const handleExport = async () => {
    try {
      setExporting(true)
      const response = await api.get('/api/alerts/history?limit=100')
      const data = response.data?.alerts || []
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const link = document.createElement('a')
      link.href = url
      link.download = `alert-log-${Date.now()}.json`
      document.body.appendChild(link)
      link.click()
      link.remove()
      URL.revokeObjectURL(url)
      toast.success('Alert log exported')
    } catch (error) {
      toast.error('Failed to export log')
      console.error('Failed to export log', error)
    } finally {
      setExporting(false)
    }
  }

  return (
    <PageShell
      icon={Activity}
      title="Live Event Stream"
      description="Review the chronological stream of events captured by the monitoring service."
      actions={
        <button
          type="button"
          onClick={handleExport}
          disabled={exporting}
          className={`${componentStyles.button.base} ${componentStyles.button.secondary}`}
        >
          Export log
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
          <div className="flex items-center justify-between mb-4">
            <h2 className={typography.h4}>Live feed</h2>
            <div className="flex items-center gap-2">
              <button
                type="button"
                onClick={handleRefresh}
                className={`${componentStyles.button.base} ${componentStyles.button.secondary} text-sm`}
              >
                <RefreshCcw className="w-4 h-4 mr-1" />
                Refresh
              </button>
              <button
                type="button"
                onClick={toggleStreaming}
                className={`${componentStyles.button.base} ${componentStyles.button.primary} text-sm`}
              >
                {streaming ? (
                  <>
                    <PauseCircle className="w-4 h-4 mr-1" />
                    Pause stream
                  </>
                ) : (
                  <>
                    <PlayCircle className="w-4 h-4 mr-1" />
                    Start stream
                  </>
                )}
              </button>
            </div>
          </div>
          <div className="rounded-lg border border-gray-200 divide-y max-h-[420px] overflow-y-auto">
            {loading ? (
              <div className="p-6 text-center text-sm text-gray-600">Loading live events...</div>
            ) : events.length === 0 ? (
              <div className="p-6 text-center text-sm text-gray-600">No events detected in the last hour.</div>
            ) : (
              events.map((event, index) => (
                <div key={index} className="p-4 flex items-start justify-between gap-4">
                  <div>
                    <p className="text-sm font-semibold text-gray-900">
                      {event.threat_type || event.type || 'Threat detection'}
                    </p>
                    <p className="text-xs text-gray-500">
                      Source: {event.source_ip || event.ip || 'Unknown'} ·{' '}
                      {event.timestamp || event.time || ''}
                    </p>
                    {event.details && (
                      <p className="text-xs text-gray-600 mt-1 line-clamp-2">{event.details}</p>
                    )}
                  </div>
                  <span
                    className={`${componentStyles.badge.base} ${
                      (event.severity || '').toLowerCase() === 'critical'
                        ? componentStyles.badge.error
                        : (event.severity || '').toLowerCase() === 'high'
                        ? componentStyles.badge.warning
                        : componentStyles.badge.info
                    }`}
                  >
                    {(event.severity || 'info').toUpperCase()}
                  </span>
                </div>
              ))
            )}
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          className={componentStyles.card}
        >
          <h2 className={`${typography.h4} flex items-center gap-2`}>
            <Filter className="w-4 h-4" />
            Filters
          </h2>
          <div className="mt-4 space-y-3">
            {['Severity', 'Source type', 'Time range'].map((label) => (
              <div key={label}>
                <p className="text-sm font-medium text-gray-700">{label}</p>
                <div className="mt-2 h-10 rounded-lg border border-gray-300 bg-gray-50 flex items-center px-3 text-sm text-gray-500">
                  Configure in backend
                </div>
              </div>
            ))}
          </div>
        </motion.div>
      </div>
    </PageShell>
  )
}
