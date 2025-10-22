import { useEffect, useState } from 'react'
import { motion } from 'framer-motion'
import { Monitor, Plus, Usb, Server, RefreshCcw } from 'lucide-react'
import toast from 'react-hot-toast'
import PageShell from '../components/PageShell'
import { componentStyles, typography } from '../styles/designSystem'
import api from '../services/api'

const initialFormState = {
  name: '',
  type: 'Agent',
  ip: '',
  mac_address: '',
  os: 'Windows 11'
}

export default function DevicesPage() {
  const [devices, setDevices] = useState([])
  const [summary, setSummary] = useState(null)
  const [loading, setLoading] = useState(true)
  const [showProvisionForm, setShowProvisionForm] = useState(false)
  const [form, setForm] = useState(initialFormState)
  const [submitting, setSubmitting] = useState(false)

  const fetchDevices = async (showIndicator = false) => {
    try {
      if (showIndicator) {
        setLoading(true)
      }
      const response = await api.get('network/devices')
      setDevices(response.data?.devices || [])
      setSummary(response.data?.summary || null)
    } catch (error) {
      toast.error('Unable to load devices')
      console.error('Failed to fetch devices', error)
    } finally {
      if (showIndicator) {
        setLoading(false)
      }
    }
  }

  useEffect(() => {
    fetchDevices(true)
  }, [])

  const handleInputChange = (event) => {
    const { name, value } = event.target
    setForm((prev) => ({ ...prev, [name]: value }))
  }

  const provisionDevice = async (event) => {
    event.preventDefault()
    setSubmitting(true)
    try {
      const payload = {
        ...form,
        enrollment_token: `ENROLL-${Date.now()}`
      }
      const response = await api.post('network/devices/provision', payload)
      toast.success(response.data?.message || 'Device enrolled')
      setShowProvisionForm(false)
      setForm(initialFormState)
      await fetchDevices(true)
    } catch (error) {
      toast.error(error.response?.data?.message || 'Failed to enroll device')
      console.error('Failed to provision device', error)
    } finally {
      setSubmitting(false)
    }
  }

  const statusBadge = (status) => {
    const normalized = (status || '').toLowerCase()
    if (normalized === 'active') return componentStyles.badge.success
    if (normalized === 'suspicious') return componentStyles.badge.warning
    if (normalized === 'high') return componentStyles.badge.error
    return componentStyles.badge.info
  }

  return (
    <PageShell
      icon={Monitor}
      title="Connected Devices"
      description="Manage the collectors, agents, and gateways connected to the platform."
      actions={
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => fetchDevices(true)}
            className={`${componentStyles.button.base} ${componentStyles.button.secondary}`}
          >
            <RefreshCcw className="w-4 h-4 mr-2" />
            Refresh
          </button>
          <button
            type="button"
            onClick={() => setShowProvisionForm(true)}
            className={`${componentStyles.button.base} ${componentStyles.button.primary}`}
          >
            <Plus className="w-4 h-4 mr-2" />
            Add device
          </button>
        </div>
      }
    >
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25 }}
        className={componentStyles.card}
      >
        <div className="flex flex-col gap-4">
          {summary && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
              {[
                { label: 'Total devices', value: summary.total_devices },
                { label: 'Active', value: summary.active_devices },
                { label: 'High risk', value: summary.high_risk_devices },
                { label: 'Traffic (KB/s)', value: Math.round((summary.total_traffic || 0) / 1024) }
              ].map((item) => (
                <div key={item.label} className="bg-gray-50 rounded-lg p-4 border border-gray-100">
                  <p className="text-xs uppercase text-gray-500">{item.label}</p>
                  <p className="text-lg font-semibold text-gray-900">{item.value}</p>
                </div>
              ))}
            </div>
          )}

          <div className="overflow-x-auto">
            <table className="min-w-full text-sm">
              <thead>
                <tr className="text-left text-gray-500">
                  <th className="py-3">Name</th>
                  <th className="py-3">Type</th>
                  <th className="py-3">Status</th>
                  <th className="py-3">IP</th>
                  <th className="py-3">Last seen</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-100">
                {loading ? (
                  <tr>
                    <td className="py-6 text-center text-gray-500" colSpan={5}>
                      Loading devices...
                    </td>
                  </tr>
                ) : devices.length === 0 ? (
                  <tr>
                    <td className="py-6 text-center text-gray-500" colSpan={5}>
                      No devices discovered yet.
                    </td>
                  </tr>
                ) : (
                  devices.map((device) => (
                    <tr key={device.id || device.ip} className="text-gray-700">
                      <td className="py-3 flex items-center gap-3">
                        <Server className="w-4 h-4 text-gray-400" />
                        {device.name}
                      </td>
                      <td className="py-3">{device.type}</td>
                      <td className="py-3">
                        <span className={`${componentStyles.badge.base} ${statusBadge(device.status)}`}>
                          {(device.status || 'unknown').toUpperCase()}
                        </span>
                      </td>
                      <td className="py-3 text-gray-600">{device.ip}</td>
                      <td className="py-3 text-gray-500">{device.last_seen || 'Unknown'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </motion.div>

      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
        className={componentStyles.card}
      >
        <div className="flex items-center gap-3 mb-3">
          <Usb className="w-5 h-5 text-blue-600" />
          <h2 className={typography.h4}>Provisioning</h2>
        </div>
        <p className={typography.small}>
          Device provisioning scripts can be downloaded from the deployment portal. Install the agent, then link it
          here by entering the provided enrollment token.
        </p>
      </motion.div>

      {showProvisionForm && (
        <div className="fixed inset-0 bg-black/30 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-white rounded-xl shadow-lg max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-900">Enroll new device</h2>
              <button
                type="button"
                onClick={() => setShowProvisionForm(false)}
                className="text-sm text-blue-600 hover:underline"
              >
                Cancel
              </button>
            </div>
            <form className="space-y-4" onSubmit={provisionDevice}>
              <div>
                <label className="block text-xs uppercase text-gray-500 mb-1">Device name</label>
                <input
                  required
                  name="name"
                  value={form.name}
                  onChange={handleInputChange}
                  className={componentStyles.input.base}
                />
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs uppercase text-gray-500 mb-1">Type</label>
                  <select
                    name="type"
                    value={form.type}
                    onChange={handleInputChange}
                    className={componentStyles.input.base}
                  >
                    <option value="Agent">Endpoint agent</option>
                    <option value="Collector">Collector</option>
                    <option value="Gateway">Gateway</option>
                    <option value="Sensor">Sensor</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs uppercase text-gray-500 mb-1">Operating system</label>
                  <input
                    name="os"
                    value={form.os}
                    onChange={handleInputChange}
                    className={componentStyles.input.base}
                  />
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs uppercase text-gray-500 mb-1">IPv4 address</label>
                  <input
                    name="ip"
                    value={form.ip}
                    onChange={handleInputChange}
                    className={componentStyles.input.base}
                    placeholder="192.168.1.25"
                  />
                </div>
                <div>
                  <label className="block text-xs uppercase text-gray-500 mb-1">MAC address</label>
                  <input
                    name="mac_address"
                    value={form.mac_address}
                    onChange={handleInputChange}
                    className={componentStyles.input.base}
                    placeholder="00-11-22-33-44-55"
                  />
                </div>
              </div>
              <div className="flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowProvisionForm(false)}
                  className={`${componentStyles.button.base} ${componentStyles.button.secondary}`}
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={submitting}
                  className={`${componentStyles.button.base} ${componentStyles.button.primary}`}
                >
                  {submitting ? 'Enrolling…' : 'Enroll device'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </PageShell>
  )
}
