"""
Alert System for Threat Notifications
Sends SMS, WhatsApp, Email notifications when threats are detected
"""

import logging
import requests
from datetime import datetime
from typing import Dict, List, Any
import json
import os

logger = logging.getLogger(__name__)

class AlertSystem:
    """Comprehensive alert system for threat notifications."""

    def __init__(self):
        self.alert_channels = {
            'sms': True,
            'whatsapp': True,
            'email': True,
            'slack': False,
            'telegram': False
        }

        # Configuration (should be in environment variables for production)
        self.config = {
            'twilio_account_sid': os.getenv('TWILIO_ACCOUNT_SID', 'demo_sid'),
            'twilio_auth_token': os.getenv('TWILIO_AUTH_TOKEN', 'demo_token'),
            'twilio_phone_number': os.getenv('TWILIO_PHONE_NUMBER', '+1234567890'),
            'alert_phone_numbers': os.getenv('ALERT_PHONE_NUMBERS', '+1234567890').split(','),
            'smtp_server': os.getenv('SMTP_SERVER', 'smtp.gmail.com'),
            'smtp_port': int(os.getenv('SMTP_PORT', '587')),
            'email_from': os.getenv('EMAIL_FROM', 'security@adaptivesuite.com'),
            'email_to': os.getenv('EMAIL_TO', 'admin@example.com').split(','),
            'email_password': os.getenv('EMAIL_PASSWORD', ''),
            'whatsapp_api_url': os.getenv('WHATSAPP_API_URL', 'https://api.whatsapp.com/send'),
        }

        self.alert_history = []
        self.max_history = 100

    def send_threat_alert(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Send alert through all configured channels when a threat is detected.

        Args:
            threat_data: Dictionary containing threat information
                - threat_type: Type of threat (e.g., 'sql_injection', 'ddos', 'malware')
                - severity: Severity level (low, medium, high, critical)
                - source_ip: IP address of the threat source
                - timestamp: When the threat was detected
                - details: Additional threat details
                - action_taken: How the threat was handled
        """

        classification = self._classify_threat(threat_data)
        threat_data.setdefault('threat_type', classification['name'])
        threat_data.setdefault('category', classification['category'])
        threat_data.setdefault('severity', classification['severity'])
        threat_data.setdefault('tactics', classification['tactics'])

        results = {
            'alert_id': f"ALERT-{datetime.now().strftime('%Y%m%d%H%M%S')}",
            'timestamp': datetime.now().isoformat(),
            'threat_data': threat_data,
            'notifications_sent': {}
        }

        # Prepare alert message
        alert_message = self._format_alert_message(threat_data)
        alert_html = self._format_alert_html(threat_data)

        # Send through all enabled channels
        if self.alert_channels['sms']:
            sms_result = self._send_sms_alert(alert_message, threat_data)
            results['notifications_sent']['sms'] = sms_result

        if self.alert_channels['whatsapp']:
            whatsapp_result = self._send_whatsapp_alert(alert_message, threat_data)
            results['notifications_sent']['whatsapp'] = whatsapp_result

        if self.alert_channels['email']:
            email_result = self._send_email_alert(alert_message, alert_html, threat_data)
            results['notifications_sent']['email'] = email_result

        # Store in history
        self.alert_history.append(results)
        if len(self.alert_history) > self.max_history:
            self.alert_history = self.alert_history[-self.max_history:]

        logger.info(f"Threat alert sent: {results['alert_id']}")
        return results

    def _classify_threat(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Infer a likely threat type/category from available indicators."""
        details = (threat_data.get('details') or '').lower()
        vector = (threat_data.get('vector') or '').lower()
        protocol = (threat_data.get('protocol') or threat_data.get('transport_protocol') or '').lower()

        candidate_ports = []
        for key in ('destination_port', 'dest_port', 'port'):
            value = threat_data.get(key)
            if value is None:
                continue
            try:
                candidate_ports.append(int(value))
            except (ValueError, TypeError):
                continue

        heuristics = [
            {
                'name': 'SQL Injection Attack',
                'category': 'Application Exploit',
                'severity': 'high',
                'tactics': ['Initial Access', 'Execution'],
                'match': lambda: any(term in details for term in ['sql injection', 'union select', 'or 1=1'])
            },
            {
                'name': 'Distributed Denial of Service',
                'category': 'Network Flooding',
                'severity': 'critical',
                'tactics': ['Impact'],
                'match': lambda: 'ddos' in details or ('flood' in details and protocol in {'udp', 'icmp'})
            },
            {
                'name': 'Brute Force Login Attempt',
                'category': 'Credential Access',
                'severity': 'medium',
                'tactics': ['Credential Access'],
                'match': lambda: any(term in details for term in ['failed login', 'password guess', 'brute force'])
            },
            {
                'name': 'Malware Beaconing Activity',
                'category': 'Command and Control',
                'severity': 'high',
                'tactics': ['Command and Control'],
                'match': lambda: 'beacon' in details or 'malware' in details or 'callback' in details
            },
            {
                'name': 'Suspicious PowerShell Execution',
                'category': 'Execution',
                'severity': 'medium',
                'tactics': ['Execution'],
                'match': lambda: 'powershell' in details or '.ps1' in details
            },
            {
                'name': 'Ransomware Behavior Detected',
                'category': 'Impact',
                'severity': 'critical',
                'tactics': ['Impact', 'Exfiltration'],
                'match': lambda: any(term in details for term in ['ransom', 'encrypted files', 'shadow copy'])
            },
            {
                'name': 'Lateral Movement Attempt',
                'category': 'Lateral Movement',
                'severity': 'high',
                'tactics': ['Lateral Movement'],
                'match': lambda: any(port in {3389, 445, 5985, 5986} for port in candidate_ports)
            },
            {
                'name': 'Suspicious File Transfer',
                'category': 'Exfiltration',
                'severity': 'medium',
                'tactics': ['Exfiltration'],
                'match': lambda: any(term in details for term in ['ftp transfer', 'scp', 'sftp', 'large outbound'])
            },
            {
                'name': 'Zero-Day Exploit Attempt',
                'category': 'Advanced Threat',
                'severity': 'critical',
                'tactics': ['Initial Access', 'Execution'],
                'match': lambda: 'zero-day' in details or '0day' in details or 'unknown exploit' in details
            },
            {
                'name': 'AI-Driven Phishing Campaign',
                'category': 'Social Engineering',
                'severity': 'medium',
                'tactics': ['Initial Access'],
                'match': lambda: 'phishing' in details or 'impersonation' in details or 'email lure' in details
            }
        ]

        for heuristic in heuristics:
            try:
                if heuristic['match']():
                    return heuristic
            except Exception:
                continue

        severity = (threat_data.get('severity') or 'medium').lower()
        default_map = {
            'low': ('Reconnaissance Activity', ['Reconnaissance']),
            'medium': ('Potential Unauthorized Access', ['Credential Access']),
            'high': ('High-Risk Intrusion', ['Execution']),
            'critical': ('Critical Infrastructure Attack', ['Impact'])
        }
        name, tactics = default_map.get(severity, ('Unknown Suspicious Activity', ['Reconnaissance']))

        return {
            'name': name,
            'category': 'General Threat',
            'severity': severity,
            'tactics': tactics
        }

    def _format_alert_message(self, threat_data: Dict) -> str:
        """Format alert message for SMS/WhatsApp."""
        severity_emoji = {
            'low': '⚠️',
            'medium': '🟡',
            'high': '🔴',
            'critical': '🚨'
        }

        emoji = severity_emoji.get(threat_data.get('severity', 'medium'), '⚠️')

        message = f"""{emoji} SECURITY ALERT - Adaptive Security Suite

🛡️ Threat Type: {threat_data.get('threat_type', 'Unknown')}
📊 Severity: {threat_data.get('severity', 'UNKNOWN').upper()}
🌐 Source IP: {threat_data.get('source_ip', 'Unknown')}
🕐 Detected: {threat_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}

📝 Details:
{threat_data.get('details', 'No additional details')}

✅ Action Taken:
{threat_data.get('action_taken', 'Threat blocked and logged')}

🔒 System Status: Protected
📈 Confidence: {threat_data.get('confidence', 95)}%

View dashboard: http://127.0.0.1:5000/suite/status
"""
        return message

    def _format_alert_html(self, threat_data: Dict) -> str:
        """Format alert message for email (HTML)."""
        severity_color = {
            'low': '#FFA500',
            'medium': '#FFD700',
            'high': '#FF4500',
            'critical': '#DC143C'
        }

        color = severity_color.get(threat_data.get('severity', 'medium'), '#FFD700')

        html = f"""
<!DOCTYPE html>
<html>
<head>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; background-color: #000; color: #0f0; padding: 20px; }}
        .container {{ max-width: 600px; margin: 0 auto; background-color: #111; border: 2px solid #0f0; border-radius: 8px; padding: 30px; }}
        .header {{ background-color: {color}; color: #000; padding: 20px; border-radius: 5px; text-align: center; margin-bottom: 20px; }}
        .header h1 {{ margin: 0; font-size: 24px; }}
        .section {{ background-color: #1a1a1a; border: 1px solid #0f0; padding: 15px; margin: 15px 0; border-radius: 5px; }}
        .section-title {{ color: #0f0; font-weight: bold; font-size: 16px; margin-bottom: 10px; }}
        .info-row {{ display: flex; justify-content: space-between; padding: 8px 0; border-bottom: 1px solid #333; }}
        .info-label {{ color: #0a0; }}
        .info-value {{ color: #0f0; font-weight: bold; }}
        .action-taken {{ background-color: #002200; border-left: 4px solid #0f0; padding: 15px; margin: 15px 0; }}
        .footer {{ text-align: center; margin-top: 20px; padding-top: 20px; border-top: 1px solid #0f0; color: #0a0; font-size: 12px; }}
        .button {{ display: inline-block; background-color: #0f0; color: #000; padding: 12px 24px; text-decoration: none; border-radius: 5px; font-weight: bold; margin-top: 15px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🚨 SECURITY ALERT</h1>
            <p style="margin: 5px 0 0 0;">Adaptive Security Suite</p>
        </div>

        <div class="section">
            <div class="section-title">🛡️ THREAT INFORMATION</div>
            <div class="info-row">
                <span class="info-label">Threat Type:</span>
                <span class="info-value">{threat_data.get('threat_type', 'Unknown')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Severity Level:</span>
                <span class="info-value" style="color: {color};">{threat_data.get('severity', 'UNKNOWN').upper()}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Source IP:</span>
                <span class="info-value">{threat_data.get('source_ip', 'Unknown')}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Detection Time:</span>
                <span class="info-value">{threat_data.get('timestamp', datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</span>
            </div>
            <div class="info-row">
                <span class="info-label">Confidence:</span>
                <span class="info-value">{threat_data.get('confidence', 95)}%</span>
            </div>
        </div>

        <div class="section">
            <div class="section-title">📝 THREAT DETAILS</div>
            <p style="color: #0f0; line-height: 1.6;">{threat_data.get('details', 'No additional details available')}</p>
        </div>

        <div class="action-taken">
            <div class="section-title">✅ ACTION TAKEN</div>
            <p style="color: #0f0; margin: 0; line-height: 1.6;">{threat_data.get('action_taken', 'Threat was automatically blocked and logged for analysis')}</p>
        </div>

        <div class="section">
            <div class="section-title">🔒 SYSTEM STATUS</div>
            <div class="info-row">
                <span class="info-label">Protection Status:</span>
                <span class="info-value">✓ ACTIVE</span>
            </div>
            <div class="info-row">
                <span class="info-label">Firewall:</span>
                <span class="info-value">✓ ENABLED</span>
            </div>
            <div class="info-row">
                <span class="info-label">IDS/IPS:</span>
                <span class="info-value">✓ MONITORING</span>
            </div>
        </div>

        <div style="text-align: center;">
            <a href="http://127.0.0.1:5000/suite/status" class="button">VIEW DASHBOARD</a>
        </div>

        <div class="footer">
            <p>Adaptive Security Suite - AI-Powered Cybersecurity Platform</p>
            <p>This is an automated alert. Please do not reply to this email.</p>
        </div>
    </div>
</body>
</html>
"""
        return html

    def _send_sms_alert(self, message: str, threat_data: Dict) -> Dict:
        """Send SMS alert via Twilio (simulated in demo mode)."""
        try:
            # In production, use Twilio API
            # from twilio.rest import Client
            # client = Client(self.config['twilio_account_sid'], self.config['twilio_auth_token'])

            # For demo purposes, simulate sending
            logger.info(f"SMS Alert would be sent to: {self.config['alert_phone_numbers']}")
            logger.info(f"SMS Content: {message[:100]}...")

            return {
                'status': 'success',
                'method': 'sms',
                'recipients': self.config['alert_phone_numbers'],
                'sent_at': datetime.now().isoformat(),
                'message': 'SMS alert sent successfully (demo mode)'
            }

        except Exception as e:
            logger.error(f"Failed to send SMS alert: {e}")
            return {
                'status': 'failed',
                'method': 'sms',
                'error': str(e)
            }

    def _send_whatsapp_alert(self, message: str, threat_data: Dict) -> Dict:
        """Send WhatsApp alert (simulated in demo mode)."""
        try:
            # In production, use WhatsApp Business API or Twilio WhatsApp
            logger.info(f"WhatsApp Alert would be sent to: {self.config['alert_phone_numbers']}")
            logger.info(f"WhatsApp Content: {message[:100]}...")

            return {
                'status': 'success',
                'method': 'whatsapp',
                'recipients': self.config['alert_phone_numbers'],
                'sent_at': datetime.now().isoformat(),
                'message': 'WhatsApp alert sent successfully (demo mode)'
            }

        except Exception as e:
            logger.error(f"Failed to send WhatsApp alert: {e}")
            return {
                'status': 'failed',
                'method': 'whatsapp',
                'error': str(e)
            }

    def _send_email_alert(self, message: str, html: str, threat_data: Dict) -> Dict:
        """Send email alert (simulated in demo mode)."""
        try:
            # In production, use SMTP
            # import smtplib
            # from email.mime.multipart import MIMEMultipart
            # from email.mime.text import MIMEText

            logger.info(f"Email Alert would be sent to: {self.config['email_to']}")
            logger.info(f"Email Subject: Security Alert - {threat_data.get('threat_type', 'Unknown Threat')}")

            return {
                'status': 'success',
                'method': 'email',
                'recipients': self.config['email_to'],
                'sent_at': datetime.now().isoformat(),
                'subject': f"Security Alert - {threat_data.get('threat_type', 'Unknown Threat')}",
                'message': 'Email alert sent successfully (demo mode)'
            }

        except Exception as e:
            logger.error(f"Failed to send email alert: {e}")
            return {
                'status': 'failed',
                'method': 'email',
                'error': str(e)
            }

    def get_alert_history(self, limit: int = 10) -> List[Dict]:
        """Get recent alert history."""
        return self.alert_history[-limit:]

    def test_alert_system(self) -> Dict:
        """Send a test alert through all channels."""
        test_threat = {
            'threat_type': 'System Test',
            'severity': 'low',
            'source_ip': '127.0.0.1',
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'details': 'This is a test alert to verify the alert system is working correctly.',
            'action_taken': 'No action required - this is a test.',
            'confidence': 100
        }

        return self.send_threat_alert(test_threat)


# Global alert system instance
_alert_system_instance = None

def get_alert_system() -> AlertSystem:
    """Get the global alert system instance."""
    global _alert_system_instance
    if _alert_system_instance is None:
        _alert_system_instance = AlertSystem()
    return _alert_system_instance
