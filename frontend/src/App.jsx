
import { useEffect, useState } from 'react'
import './App.css'

const API_URL = (
  import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'
).replace(/\/$/, '')

function App() {
  const [emails, setEmails] = useState([])
  const [quarantined, setQuarantined] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [successMessage, setSuccessMessage] = useState('')
  const [activePage, setActivePage] = useState('Dashboard')
  const [expandedEmail, setExpandedEmail] = useState(null)
  const [quarantiningId, setQuarantiningId] = useState(null)

  // Manual Phishing Check State
  const [messageInput, setMessageInput] = useState('')
  const [urlInput, setUrlInput] = useState('')
  const [manualLoading, setManualLoading] = useState(false)
  const [manualResult, setManualResult] = useState(null)
  const [manualError, setManualError] = useState('')

  // User & OAuth State
  const [connected, setConnected] = useState(false)
  const [userEmail, setUserEmail] = useState('')
  const [oauthLoading, setOauthLoading] = useState(false)

  const [sessionToken, setSessionToken] = useState(() => {
    return localStorage.getItem('zg_session_token') || ''
  })

  // Helper: Request headers with session token
  const getAuthHeaders = (tokenOverride = null) => {
    const headers = {
      'Content-Type': 'application/json'
    }

    const token =
      tokenOverride ||
      sessionToken ||
      localStorage.getItem('zg_session_token')

    if (token) {
      headers['Authorization'] = `Bearer ${token}`
    }

    return headers
  }

  // ============================================================
  // CONNECT EMAIL FLOW
  // ============================================================

  const startGoogleOAuth = () => {
    if (oauthLoading) return

    setError('')
    setOauthLoading(true)

    const currentOrigin = window.location.origin
    const loginUrl =
      `${API_URL}/auth/google/login?frontend_url=${encodeURIComponent(
        currentOrigin
      )}`

    console.log('[ZeroGuard] Starting fresh Google OAuth flow:', {
      api: API_URL,
      frontendOrigin: currentOrigin,
      loginEndpoint: `${API_URL}/auth/google/login`
    })

    window.location.assign(loginUrl)
  }

  const handleConnectEmail = () => {
    startGoogleOAuth()
  }

  const handleSwitchAccount = async () => {
    if (oauthLoading) return

    setError('')
    setOauthLoading(true)

    const oldToken =
      sessionToken || localStorage.getItem('zg_session_token') || ''

    try {
      if (oldToken) {
        await fetch(`${API_URL}/auth/disconnect`, {
          method: 'POST',
          headers: getAuthHeaders(oldToken),
          cache: 'no-store'
        })
      }
    } catch (err) {
      console.warn('[ZeroGuard] Previous session disconnect failed:', err)
    }

    localStorage.removeItem('zg_session_token')
    localStorage.removeItem('zg_user_email')
    setSessionToken('')
    setUserEmail('')
    setConnected(false)
    setEmails([])
    setQuarantined([])
    setExpandedEmail(null)

    const currentOrigin = window.location.origin
    const loginUrl =
      `${API_URL}/auth/google/login?frontend_url=${encodeURIComponent(
        currentOrigin
      )}`

    console.log('[ZeroGuard] Switching Gmail account with a fresh OAuth flow.')
    window.location.assign(loginUrl)
  }

  // ============================================================
  // DISCONNECT EMAIL
  // ============================================================

  const handleDisconnect = async () => {
    try {
      console.log(
        '[ZeroGuard] Disconnecting account...'
      )

      await fetch(
        `${API_URL}/auth/disconnect`,
        {
          method: 'POST',
          headers: getAuthHeaders()
        }
      )
    } catch (err) {
      console.warn(
        'Disconnect request failed:',
        err
      )
    } finally {
      localStorage.removeItem(
        'zg_session_token'
      )

      localStorage.removeItem(
        'zg_user_email'
      )

      setSessionToken('')
      setUserEmail('')
      setConnected(false)
      setEmails([])
      setQuarantined([])

      setSuccessMessage(
        'Account disconnected successfully.'
      )

      setTimeout(() => {
        setSuccessMessage('')
      }, 4000)
    }
  }

  // ============================================================
  // CHECK AUTH STATUS
  // ============================================================

  const checkAuthStatus = async (
    tokenOverride = null
  ) => {
    try {
      const response = await fetch(
        `${API_URL}/auth/status`,
        {
          headers: getAuthHeaders(tokenOverride),
          cache: 'no-store'
        }
      )

      const data = await response.json()

      console.log(
        '[ZeroGuard] /auth/status response:',
        data
      )

      if (
        data.status === 'success' &&
        data.connected
      ) {
        setConnected(true)

        const email =
          data.email ||
          localStorage.getItem(
            'zg_user_email'
          ) ||
          ''

        setUserEmail(email)

        if (email) {
          localStorage.setItem(
            'zg_user_email',
            email
          )
        }

        return true
      }

      setConnected(false)

      return false
    } catch (err) {
      console.error(
        '[ZeroGuard] Error checking auth status:',
        err
      )

      return false
    }
  }

  // ============================================================
  // FETCH INBOX EMAILS
  // ============================================================

  const fetchEmails = async (
    tokenOverride = null
  ) => {
    try {
      const response = await fetch(
        `${API_URL}/emails`,
        {
          headers: getAuthHeaders(tokenOverride)
        }
      )

      if (response.status === 401) {
        setConnected(false)
        setEmails([])
        return
      }

      if (!response.ok) {
        throw new Error(
          'Failed to fetch emails'
        )
      }

      const data = await response.json()

      console.log(
        '[ZeroGuard] /emails response:',
        data
      )

      if (data.status === 'success') {
        setEmails(data.emails || [])
        setConnected(true)
      } else if (
        data.status === 'unauthenticated'
      ) {
        setConnected(false)
        setEmails([])
      } else {
        setError(
          data.error ||
          'Failed to load emails'
        )
      }
    } catch (err) {
      console.error(
        '[ZeroGuard] Error fetching emails:',
        err
      )

      setError(
        'Unable to connect to ZeroGuard backend.'
      )
    }
  }

  // ============================================================
  // FETCH QUARANTINED EMAILS
  // ============================================================

  const fetchQuarantinedEmails = async (
    tokenOverride = null
  ) => {
    try {
      const response = await fetch(
        `${API_URL}/quarantine`,
        {
          headers: getAuthHeaders(tokenOverride)
        }
      )

      if (response.status === 401) {
        setQuarantined([])
        return
      }

      if (!response.ok) {
        throw new Error(
          'Failed to fetch quarantined emails'
        )
      }

      const data = await response.json()

      console.log(
        '[ZeroGuard] /quarantine response:',
        data
      )

      if (data.status === 'success') {
        setQuarantined(
          data.emails || []
        )
      }
    } catch (err) {
      console.error(
        '[ZeroGuard] Error fetching quarantined emails:',
        err
      )
    }
  }

  // ============================================================
  // LOAD ALL DATA
  // ============================================================

  const loadDashboardData = async (
    tokenOverride = null
  ) => {
    try {
      setLoading(true)

      const isAuthed =
        await checkAuthStatus(
          tokenOverride
        )

      if (isAuthed) {
        await Promise.all([
          fetchEmails(tokenOverride),
          fetchQuarantinedEmails(
            tokenOverride
          )
        ])
      } else {
        setEmails([])
        setQuarantined([])
      }
    } finally {
      setLoading(false)
    }
  }

  // ============================================================
  // INITIAL LOAD & OAUTH CALLBACK
  // ============================================================

  useEffect(() => {
    const queryParams =
      new URLSearchParams(
        window.location.search
      )

    const tokenFromUrl =
      queryParams.get(
        'session_token'
      )

    const emailFromUrl =
      queryParams.get('email')

    const authError =
      queryParams.get('auth_error')

    const authStatus =
      queryParams.get('status')

    console.log(
      '[ZeroGuard] App initialized. OAuth params:',
      {
        has_token: Boolean(
          tokenFromUrl
        ),
        has_email: Boolean(
          emailFromUrl
        ),
        status: authStatus,
        has_auth_error: Boolean(
          authError
        )
      }
    )

    // ==========================================================
    // SUCCESSFUL GOOGLE OAUTH
    // ==========================================================

    if (tokenFromUrl) {
      console.log(
        '[ZeroGuard] OAuth callback successful. Saving session.'
      )

      // Save session token
      localStorage.setItem(
        'zg_session_token',
        tokenFromUrl
      )

      setSessionToken(
        tokenFromUrl
      )

      // Save email
      if (emailFromUrl) {
        const decodedEmail =
          decodeURIComponent(
            emailFromUrl
          )

        localStorage.setItem(
          'zg_user_email',
          decodedEmail
        )

        setUserEmail(
          decodedEmail
        )
      }

      // Immediately show connected state
      setConnected(true)
      setOauthLoading(false)

      setError('')

      setSuccessMessage(
        '✓ Successfully connected your Gmail account!'
      )

      setTimeout(() => {
        setSuccessMessage('')
      }, 5000)

      // Remove OAuth parameters from URL
      window.history.replaceState(
        {},
        document.title,
        window.location.pathname
      )

      // Verify session and load emails
      loadDashboardData(
        tokenFromUrl
      )

      return
    }

    // ==========================================================
    // OAUTH ERROR
    // ==========================================================

    if (authError) {
      const decodedErr =
        decodeURIComponent(
          authError
        )

      console.error(
        '[ZeroGuard] OAuth callback returned error:',
        decodedErr
      )

      setConnected(false)
      setOauthLoading(false)

      localStorage.removeItem('zg_session_token')
      localStorage.removeItem('zg_user_email')
      setSessionToken('')
      setUserEmail('')

      setError(
        `Google authorization failed: ${decodedErr}`
      )

      window.history.replaceState(
        {},
        document.title,
        window.location.pathname
      )

      setLoading(false)

      return
    }

    // ==========================================================
    // NORMAL PAGE LOAD
    // ==========================================================

    const storedToken =
      localStorage.getItem(
        'zg_session_token'
      )

    const storedEmail =
      localStorage.getItem(
        'zg_user_email'
      )

    if (storedEmail) {
      setUserEmail(
        storedEmail
      )
    }

    if (storedToken) {
      console.log(
        '[ZeroGuard] Existing session found. Checking authentication.'
      )

      loadDashboardData(
        storedToken
      )
    } else {
      console.log(
        '[ZeroGuard] No existing session. User is disconnected.'
      )

      setLoading(false)
    }
  }, [])

  // ============================================================
  // QUARANTINE EMAIL
  // ============================================================

  const quarantineEmail = async (
    email
  ) => {
    try {
      setQuarantiningId(
        email.id
      )

      const response =
        await fetch(
          `${API_URL}/quarantine/${email.id}`,
          {
            method: 'POST',
            headers: getAuthHeaders()
          }
        )

      const data =
        await response.json()

      console.log(
        '[ZeroGuard] Quarantine response:',
        data
      )

      if (data.status === 'success') {
        setEmails(
          (previousEmails) =>
            previousEmails.filter(
              (item) =>
                item.id !== email.id
            )
        )

        await fetchQuarantinedEmails()

        setExpandedEmail(null)

        setSuccessMessage(
          '🚨 Email moved to quarantine!'
        )

        setTimeout(() => {
          setSuccessMessage('')
        }, 4000)
      } else {
        alert(
          `Failed to quarantine email: ${
            data.error ||
            'Unknown error'
          }`
        )
      }
    } catch (err) {
      console.error(
        'Quarantine error:',
        err
      )

      alert(
        'Unable to connect to ZeroGuard backend.'
      )
    } finally {
      setQuarantiningId(null)
    }
  }

  // ============================================================
  // MANUAL PHISHING CHECK FLOW
  // ============================================================

  const SAMPLE_MESSAGES = [
    {
      label: 'WhatsApp OTP Scam',
      message: 'Urgent: I accidentally sent my 6-digit WhatsApp registration code to your number. Please send it back immediately so my account is not deactivated!',
      url: ''
    },
    {
      label: 'Fake PayPal Alert',
      message: 'Your PayPal account has been restricted due to suspicious login attempts. Verify your identity within 24 hours to prevent permanent suspension.',
      url: 'http://paypa1-security-check.xyz/login'
    },
    {
      label: 'Safe Meeting Note',
      message: 'Hey Alex, just wanted to check if we are still meeting for coffee today at 3 PM at the corner cafe? Let me know!',
      url: ''
    }
  ]

  const handleAnalyzeMessage = async (e) => {
    if (e) e.preventDefault()
    const trimmedMessage = messageInput.trim()
    const trimmedUrl = urlInput.trim()

    if (!trimmedMessage && !trimmedUrl) {
      setManualError('Please enter a message or URL to analyze.')
      return
    }

    setManualLoading(true)
    setManualError('')

    try {
      const response = await fetch(`${API_URL}/analyze-message`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          message: trimmedMessage,
          url: trimmedUrl
        })
      })

      const data = await response.json()

      if (!response.ok || data.status === 'error') {
        throw new Error(data.message || 'Analysis failed. Please check your backend.')
      }

      // ------------------------------------------------------------
      // NORMALIZE MANUAL ANALYSIS RESULT
      // Always derive the displayed severity/recommendation from the
      // numeric risk score so the UI cannot show GREEN/SAFE for 100/100.
      // ------------------------------------------------------------
      const rawScore = Number(
        data.risk_score ??
        data.security?.risk_score ??
        data.result?.risk_score ??
        0
      )

      const normalizedScore = Math.max(0, Math.min(100, rawScore))

      const normalizedSeverity =
        normalizedScore >= 70
          ? 'CRITICAL'
          : normalizedScore >= 50
          ? 'HIGH'
          : normalizedScore >= 30
          ? 'MEDIUM'
          : 'LOW'

      const normalizedRecommendation =
        normalizedScore >= 70
          ? 'Quarantine / Isolate Instantly'
          : normalizedScore >= 50
          ? 'Quarantine'
          : normalizedScore >= 30
          ? 'Warn User'
          : 'Allow Email'

      // Accept all common backend field names.
      let normalizedReasons =
        data.reasons ??
        data.detection_reasons ??
        data.indicators ??
        data.security?.reasons ??
        data.result?.reasons ??
        []

      if (!Array.isArray(normalizedReasons)) {
        normalizedReasons = normalizedReasons
          ? [String(normalizedReasons)]
          : []
      }

      // Never show a "clean" message when the score is actually a threat.
      if (normalizedReasons.length === 0 && normalizedScore >= 70) {
        normalizedReasons = [
          'Critical threat indicators detected.',
          'The message contains suspicious or deceptive content.',
          ...(trimmedUrl
            ? ['A target URL was supplied for security analysis.']
            : [])
        ]
      }

      if (normalizedReasons.length === 0 && normalizedScore >= 50) {
        normalizedReasons = [
          'High-risk indicators detected by the ZeroGuard security engine.'
        ]
      }

      if (normalizedReasons.length === 0 && normalizedScore >= 30) {
        normalizedReasons = [
          'Suspicious indicators detected; user caution is recommended.'
        ]
      }

      setManualResult({
        ...data,
        risk_score: normalizedScore,
        severity: normalizedSeverity,
        recommendation: normalizedRecommendation,
        reasons: normalizedReasons
      })
    } catch (err) {
      console.error('[ZeroGuard] Manual analysis error:', err)
      setManualError(err.message || 'Unable to connect to ZeroGuard analysis engine.')
    } finally {
      setManualLoading(false)
    }
  }

  const handleClearManual = () => {
    setMessageInput('')
    setUrlInput('')
    setManualResult(null)
    setManualError('')
  }

  // ============================================================
  // STATISTICS
  // ============================================================

  const allEmailsMap =
    new Map()

  emails.forEach(
    (email) =>
      allEmailsMap.set(
        email.id,
        email
      )
  )

  quarantined.forEach(
    (email) =>
      allEmailsMap.set(
        email.id,
        email
      )
  )

  const allAnalyzedEmails =
    Array.from(
      allEmailsMap.values()
    )

  const safeCount =
    allAnalyzedEmails.filter(
      (email) =>
        email.security?.risk_level
          ?.toUpperCase() === 'LOW'
    ).length

  const suspiciousCount =
    allAnalyzedEmails.filter(
      (email) => {
        const level =
          email.security?.risk_level
            ?.toUpperCase()

        return (
          level === 'MEDIUM' ||
          level === 'HIGH'
        )
      }
    ).length

  const dangerousCount =
    allAnalyzedEmails.filter(
      (email) =>
        email.security?.risk_level
          ?.toUpperCase() ===
        'CRITICAL'
    ).length

  const quarantinedCount =
    quarantined.length

  const totalEmails =
    allAnalyzedEmails.length

  const totalThreats =
    allAnalyzedEmails.filter(
      (email) => {
        const level =
          email.security?.risk_level
            ?.toUpperCase()

        return (
          level === 'MEDIUM' ||
          level === 'HIGH' ||
          level === 'CRITICAL'
        )
      }
    ).length

  const protectionScore =
    totalEmails > 0
      ? Math.round(
          (safeCount /
            totalEmails) *
            100
        )
      : 0

  // ============================================================
  // CONNECT BANNER
  // ============================================================

  const renderConnectBanner = () => (
    <div className="connect-hero-card">
      <div className="connect-hero-icon">
        🛡️
      </div>

      <div className="connect-hero-content">
        <h2>
          Connect Your Gmail to ZeroGuard
        </h2>

        <p>
          Analyze your incoming messages for phishing attacks,
          credential harvesting, lookalike domains, and social
          engineering in real time. Each user is securely
          isolated with individual OAuth permissions.
        </p>

        <div className="hero-features-list">
          <span>✓ Multi-User Isolated</span>
          <span>✓ IntentShield AI Analysis</span>
          <span>✓ Automated Threat Quarantine</span>
          <span>✓ 100% Private & Secure</span>
        </div>
      </div>

      <button
        className="connect-email-btn large-cta"
        onClick={handleConnectEmail}
      >
        <span className="google-icon-badge">
          G
        </span>

        Connect Your Email
      </button>
    </div>
  )

  // ============================================================
  // EMAIL CARD
  // ============================================================

  const renderEmailCard = (
    email,
    index
  ) => {
    const riskLevel =
      email.security?.risk_level
        ?.toUpperCase() ||
      'QUARANTINED'

    const riskScore =
      email.security?.risk_score ??
      0

    const reasons =
      email.security?.reasons ||
      []

    const intent =
      email.security?.intent ||
      {}

    const aiAnalysis =
      email.security?.ai_analysis ||
      {}

    const attackerIntent =
      intent.attacker_intent ||
      'Not determined'

    const expectedUserAction =
      intent.expected_user_action ||
      'Not determined'

    const potentialConsequence =
      intent.potential_consequence ||
      'Not determined'

    const recommendedDefense =
      intent.recommended_defense ||
      'Manual review'

    const isExpanded =
      expandedEmail === email.id

    const isQuarantining =
      quarantiningId === email.id

    const toggleDetails = () => {
      setExpandedEmail(
        isExpanded
          ? null
          : email.id
      )
    }

    return (
      <div
        className={`email-card ${riskLevel.toLowerCase()}`}
        key={
          email.id || index
        }
      >
        <div
          className="email-main"
          onClick={toggleDetails}
        >
          <div className="email-avatar">
            {email.sender
              ? email.sender
                  .charAt(0)
                  .toUpperCase()
              : '?'}
          </div>

          <div className="email-content">
            <div className="email-title-row">
              <h3>
                {email.subject ||
                  'No Subject'}
              </h3>

              <span
                className={`risk-badge ${riskLevel.toLowerCase()}`}
              >
                {riskLevel}
              </span>
            </div>

            <p className="sender">
              {email.sender ||
                'Unknown Sender'}
            </p>

            <p className="email-preview">
              {email.body
                ? email.body
                    .substring(
                      0,
                      120
                    )
                    .replace(
                      /\n/g,
                      ' '
                    )
                : 'No email content available'}

              {email.body?.length >
              120
                ? '...'
                : ''}
            </p>
          </div>
        </div>

        <div className="email-actions">
          <div className="score">
            <span>
              Risk Score
            </span>

            <strong>
              {riskScore}/100
            </strong>
          </div>

          {riskLevel ===
            'CRITICAL' && (
            <button
              className="quarantine-btn"
              disabled={
                isQuarantining
              }
              onClick={(
                event
              ) => {
                event.stopPropagation()

                quarantineEmail(
                  email
                )
              }}
            >
              {isQuarantining
                ? 'Moving...'
                : '🛑 Quarantine'}
            </button>
          )}

          <button
            className="details-btn"
            onClick={(
              event
            ) => {
              event.stopPropagation()

              toggleDetails()
            }}
          >
            {isExpanded
              ? 'Hide'
              : 'Details'}
          </button>
        </div>

        {isExpanded && (
          <div className="threat-details">
            <h4>
              🔍 Security Analysis
            </h4>

            <div className="risk-summary">
              <div className="risk-summary-item">
                <span>
                  Risk Level
                </span>

                <strong
                  className={`risk-text ${riskLevel.toLowerCase()}`}
                >
                  {riskLevel}
                </strong>
              </div>

              <div className="risk-summary-item">
                <span>
                  Risk Score
                </span>

                <strong>
                  {riskScore}/100
                </strong>
              </div>

              <div className="risk-summary-item">
                <span>
                  AI Status
                </span>

                <strong>
                  {aiAnalysis.available
                    ? '✓ Active'
                    : '⚠ Unavailable'}
                </strong>
              </div>
            </div>

            <div className="intent-shield">
              <div className="intent-header">
                <div>
                  <span className="intent-label">
                    AI-POWERED SECURITY
                  </span>

                  <h3>
                    🧠 IntentShield
                  </h3>
                </div>

                <span className="intent-status">
                  {aiAnalysis.available
                    ? '● AI ACTIVE'
                    : 'RULE-BASED'}
                </span>
              </div>

              <p className="intent-description">
                ZeroGuard predicts what the attacker wants the user to do,
                what could happen, and how the threat should be handled.
              </p>

              <div className="intent-grid">
                <div className="intent-item">
                  <div className="intent-icon">
                    🎯
                  </div>

                  <div>
                    <span>
                      Attacker Intent
                    </span>

                    <strong>
                      {attackerIntent}
                    </strong>
                  </div>
                </div>

                <div className="intent-item">
                  <div className="intent-icon">
                    👆
                  </div>

                  <div>
                    <span>
                      Expected User Action
                    </span>

                    <strong>
                      {expectedUserAction}
                    </strong>
                  </div>
                </div>

                <div className="intent-item">
                  <div className="intent-icon">
                    💥
                  </div>

                  <div>
                    <span>
                      Potential Consequence
                    </span>

                    <strong>
                      {potentialConsequence}
                    </strong>
                  </div>
                </div>

                <div className="intent-item">
                  <div className="intent-icon">
                    🛡️
                  </div>

                  <div>
                    <span>
                      Recommended Defense
                    </span>

                    <strong>
                      {recommendedDefense}
                    </strong>
                  </div>
                </div>
              </div>
            </div>

            <div className="analysis-reasons">
              <h4>
                ⚠️ Detection Reasons
              </h4>

              {reasons.length >
              0 ? (
                <ul>
                  {reasons.map(
                    (
                      reason,
                      reasonIndex
                    ) => (
                      <li
                        key={
                          reasonIndex
                        }
                      >
                        {reason}
                      </li>
                    )
                  )}
                </ul>
              ) : (
                <p className="safe-message">
                  ✓ No security threats detected.
                </p>
              )}
            </div>

            {email.links?.length >
              0 && (
              <div className="links-section">
                <strong>
                  🔗 Links detected:
                </strong>

                {email.links.map(
                  (
                    link,
                    linkIndex
                  ) => (
                    <div
                      key={
                        linkIndex
                      }
                      className="detected-link"
                    >
                      {link}
                    </div>
                  )
                )}
              </div>
            )}
          </div>
        )}
      </div>
    )
  }

  // ============================================================
  // MANUAL PHISHING CHECK CARD / PAGE
  // ============================================================

  const renderManualCheckCard = (isFullPage = false) => {
    const manualScore = Number(manualResult?.risk_score ?? 0)
    const severityLower =
      manualScore >= 70
        ? 'critical'
        : manualScore >= 50
        ? 'high'
        : manualScore >= 30
        ? 'medium'
        : 'low'

    return (
      <section className={`manual-check-section ${isFullPage ? 'full-page' : ''}`}>
        <div className="section-header">
          <div>
            <h2>
              🔍 Check a Suspicious Message
            </h2>
            <p>
              Paste any message from WhatsApp, LinkedIn, SMS, Instagram, or an untrusted URL to analyze phishing and scam indicators.
            </p>
          </div>

          {manualResult && (
            <button
              className="manual-clear-btn"
              onClick={handleClearManual}
            >
              Clear Results
            </button>
          )}
        </div>

        <div className="manual-check-card">
          <form onSubmit={handleAnalyzeMessage} className="manual-form">
            <div className="form-group">
              <label htmlFor="manual-message-input">
                Suspicious Message Content
              </label>
              <textarea
                id="manual-message-input"
                className="manual-textarea"
                value={messageInput}
                onChange={(e) => setMessageInput(e.target.value)}
                placeholder="Paste suspicious message here (e.g. SMS, WhatsApp, LinkedIn message, or email body)..."
                rows={isFullPage ? 6 : 4}
              />
            </div>

            <div className="form-group">
              <label htmlFor="manual-url-input">
                Optional Target URL <span className="label-subtext">(or URLs will be auto-detected from message)</span>
              </label>
              <input
                id="manual-url-input"
                type="text"
                className="manual-url-input"
                value={urlInput}
                onChange={(e) => setUrlInput(e.target.value)}
                placeholder="e.g. http://paypa1-security-check.xyz/login or bit.ly/3x..."
              />
            </div>

            <div className="manual-sample-chips">
              <span className="chips-label">Try a sample:</span>
              {SAMPLE_MESSAGES.map((sample, idx) => (
                <button
                  key={idx}
                  type="button"
                  className="sample-chip"
                  onClick={() => {
                    setMessageInput(sample.message)
                    setUrlInput(sample.url)
                    setManualResult(null)
                    setManualError('')
                  }}
                >
                  {sample.label}
                </button>
              ))}
            </div>

            {manualError && (
              <div className="manual-error-banner">
                ⚠️ {manualError}
              </div>
            )}

            <div className="manual-form-actions">
              <button
                type="submit"
                className="analyze-btn"
                disabled={manualLoading || (!messageInput.trim() && !urlInput.trim())}
              >
                {manualLoading ? (
                  <>
                    <span className="spinner-icon">↻</span> Analyzing Threat...
                  </>
                ) : (
                  <>🛡️ Analyze Message</>
                )}
              </button>

              {(messageInput || urlInput || manualResult) && (
                <button
                  type="button"
                  className="manual-reset-btn"
                  onClick={handleClearManual}
                  disabled={manualLoading}
                >
                  Reset
                </button>
              )}
            </div>
          </form>

          {manualResult && (
            <div className={`manual-result-panel ${severityLower}`}>
              <div className="manual-result-header">
                <div className="manual-result-title">
                  <span className="analysis-tag">SECURITY SCAN RESULT</span>
                  <h3>Threat Evaluation</h3>
                </div>

                <div className="manual-result-badges">
                  <span className={`severity-badge ${severityLower}`}>
                    {manualScore >= 70
                      ? 'CRITICAL'
                      : manualScore >= 50
                      ? 'HIGH'
                      : manualScore >= 30
                      ? 'MEDIUM'
                      : 'LOW'}
                  </span>
                  <div className="manual-score-badge">
                    <span>Risk Score</span>
                    <strong>
                      {manualResult.risk_score}
                      <small>/100</small>
                    </strong>
                  </div>
                </div>
              </div>

              <div className="manual-recommendation-card">
                <div className="rec-icon">🛡️</div>
                <div className="rec-content">
                  <strong>Security Recommendation</strong>
                  <p>
                    {manualScore >= 70
                      ? 'Quarantine / Isolate Instantly'
                      : manualScore >= 50
                      ? 'Quarantine'
                      : manualScore >= 30
                      ? 'Warn User'
                      : 'Allow Email'}
                  </p>
                </div>
              </div>

              {manualResult.detected_urls?.length > 0 && (
                <div className="manual-urls-section">
                  <div className="urls-heading">
                    <strong>🔗 Detected Links ({manualResult.detected_urls.length})</strong>
                    <span className="safe-notice">Untrusted links are not opened automatically</span>
                  </div>
                  <div className="urls-list">
                    {manualResult.detected_urls.map((u, i) => (
                      <div key={i} className="detected-url-item">
                        <span className="url-badge-icon">⚠️</span>
                        <code className="url-text">{u}</code>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div className="manual-reasons-section">
                <h4>⚠️ Detection Reasons & Indicators</h4>
                {manualResult.reasons?.length > 0 ? (
                  <ul className="manual-reasons-list">
                    {manualResult.reasons.map((reason, idx) => (
                      <li key={idx}>
                        <span className="reason-bullet">•</span>
                        <span>{reason}</span>
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p className="clean-reason">
                    {manualScore >= 70
                      ? '⚠️ Critical threat indicators detected.'
                      : manualScore >= 50
                      ? '⚠️ High-risk indicators detected.'
                      : manualScore >= 30
                      ? '⚠️ Suspicious indicators detected.'
                      : '✓ No suspicious phishing indicators detected.'}
                  </p>
                )}
              </div>

              {manualResult.ai_analysis && (
                <div className="manual-ai-footer">
                  <span className="ai-tag">
                    {manualResult.ai_analysis.available
                      ? '✓ Verified with Featherless AI IntentShield'
                      : '⚙️ ZeroGuard Rule-Based Engine'}
                  </span>
                </div>
              )}
            </div>
          )}
        </div>
      </section>
    )
  }

  // ============================================================
  // DASHBOARD PAGE
  // ============================================================

  const renderDashboard = () => (
    <>
      {!connected &&
        renderConnectBanner()}

      <section className="stats">
        <div className="stat-card">
          <div className="stat-icon">
            📧
          </div>

          <div>
            <span>
              Total Emails
            </span>

            <strong>
              {totalEmails}
            </strong>
          </div>
        </div>

        <div className="stat-card safe-card">
          <div className="stat-icon">
            ✓
          </div>

          <div>
            <span>Safe</span>

            <strong>
              {safeCount}
            </strong>
          </div>
        </div>

        <div className="stat-card warning-card">
          <div className="stat-icon">
            ⚠
          </div>

          <div>
            <span>
              Suspicious
            </span>

            <strong>
              {suspiciousCount}
            </strong>
          </div>
        </div>

        <div className="stat-card danger-card">
          <div className="stat-icon">
            !
          </div>

          <div>
            <span>
              Dangerous
            </span>

            <strong>
              {dangerousCount}
            </strong>
          </div>
        </div>

        <div className="stat-card quarantine-card">
          <div className="stat-icon">
            🛡️
          </div>

          <div>
            <span>
              Quarantined
            </span>

            <strong>
              {quarantinedCount}
            </strong>
          </div>
        </div>
      </section>

      <section className="security-overview">
        <div>
          <span>
            Security Status
          </span>

          <h2>
            {!connected
              ? 'Connect your email account to begin scanning'
              : totalThreats === 0
              ? '✓ Your inbox is secure'
              : `⚠ ${totalThreats} threat${
                  totalThreats >
                  1
                    ? 's'
                    : ''
                } detected`}
          </h2>
        </div>

        <div className="protection-score">
          <strong>
            {protectionScore}%
          </strong>

          <span>
            Safe Emails
          </span>
        </div>
      </section>

      {renderManualCheckCard(false)}

      {renderEmailSection()}
    </>
  )

  // ============================================================
  // RECENT EMAILS SECTION
  // ============================================================

  const renderEmailSection = () => (
    <section className="email-section">
      <div className="section-header">
        <div>
          <h2>
            Recent Emails
          </h2>

          <p>
            Security analysis of incoming messages
          </p>
        </div>

        {connected && (
          <button
            className="view-btn"
            onClick={() =>
              setActivePage(
                'Emails'
              )
            }
          >
            View All →
          </button>
        )}
      </div>

      {loading &&
        emails.length ===
          0 && (
          <div className="loading">
            <div className="loading-icon">
              🛡️
            </div>

            <h3>
              Analyzing your inbox...
            </h3>

            <p>
              ZeroGuard is checking incoming emails for threats.
            </p>
          </div>
        )}

      {!loading &&
        !connected && (
          <div className="loading not-connected-box">
            <div className="loading-icon">
              🔒
            </div>

            <h3>
              Gmail Account Not Connected
            </h3>

            <p>
              Click "Connect Your Email" above to analyze your messages with ZeroGuard.
            </p>

            <button
              className="connect-email-btn"
              onClick={
                handleConnectEmail
              }
            >
              <span className="google-icon-badge">
                G
              </span>

              Connect Your Email
            </button>
          </div>
        )}

      {!loading &&
        connected &&
        emails.length ===
          0 && (
          <div className="loading">
            <div className="loading-icon">
              📭
            </div>

            <h3>
              No emails found
            </h3>

            <p>
              No emails are currently available for security analysis.
            </p>
          </div>
        )}

      {emails.length >
        0 && (
        <div className="email-list">
          {emails
            .slice(0, 5)
            .map(
              renderEmailCard
            )}
        </div>
      )}
    </section>
  )

  // ============================================================
  // ALL EMAILS PAGE
  // ============================================================

  const renderEmailsPage = () => (
    <section className="email-section">
      <div className="section-header">
        <div>
          <h2>
            ✉ All Emails
          </h2>

          <p>
            Complete security analysis of your inbox
          </p>
        </div>
      </div>

      {loading &&
        emails.length ===
          0 && (
          <div className="loading">
            <div className="loading-icon">
              🛡️
            </div>

            <h3>
              Analyzing your inbox...
            </h3>

            <p>
              ZeroGuard is checking incoming emails for threats.
            </p>
          </div>
        )}

      {!loading &&
        !connected && (
          <div className="loading not-connected-box">
            <div className="loading-icon">
              🔒
            </div>

            <h3>
              Connect Your Email
            </h3>

            <p>
              Connect your Gmail account to view and analyze your emails.
            </p>

            <button
              className="connect-email-btn"
              onClick={
                handleConnectEmail
              }
            >
              Connect Your Email
            </button>
          </div>
        )}

      {!loading &&
        connected &&
        emails.length ===
          0 && (
          <div className="loading">
            <div className="loading-icon">
              📭
            </div>

            <h3>
              No emails available
            </h3>
          </div>
        )}

      {emails.length >
        0 && (
        <div className="email-list">
          {emails.map(
            renderEmailCard
          )}
        </div>
      )}
    </section>
  )

  // ============================================================
  // THREATS PAGE
  // ============================================================

  const renderThreatsPage =
    () => {
      const threatsMap =
        new Map()

      emails.forEach(
        (email) => {
          const level =
            email.security?.risk_level
              ?.toUpperCase()

          if (
            level === 'MEDIUM' ||
            level === 'HIGH' ||
            level === 'CRITICAL'
          ) {
            threatsMap.set(
              email.id,
              email
            )
          }
        }
      )

      quarantined.forEach(
        (email) => {
          const level =
            email.security?.risk_level
              ?.toUpperCase()

          if (
            level === 'MEDIUM' ||
            level === 'HIGH' ||
            level === 'CRITICAL'
          ) {
            threatsMap.set(
              email.id,
              email
            )
          }
        }
      )

      const threats =
        Array.from(
          threatsMap.values()
        )

      return (
        <section className="email-section">
          <div className="section-header">
            <div>
              <h2>
                🚨 Detected Threats
              </h2>

              <p>
                Emails requiring your attention
              </p>
            </div>

            <span className="quarantine-count">
              {threats.length}{' '}
              detected
            </span>
          </div>

          {threats.length ===
          0 ? (
            <div className="loading">
              <div className="loading-icon">
                ✓
              </div>

              <h3>
                No threats detected
              </h3>

              <p>
                ZeroGuard hasn't detected any suspicious emails.
              </p>
            </div>
          ) : (
            <div className="email-list">
              {threats.map(
                renderEmailCard
              )}
            </div>
          )}
        </section>
      )
    }

  // ============================================================
  // QUARANTINE PAGE
  // ============================================================

  const renderQuarantinePage =
    () => (
      <section className="email-section">
        <div className="section-header">
          <div>
            <h2>
              🛑 Quarantine
            </h2>

            <p>
              Emails isolated by ZeroGuard in your Gmail account
            </p>
          </div>

          <span className="quarantine-count">
            {quarantinedCount}{' '}
            isolated
          </span>
        </div>

        {quarantined.length ===
        0 ? (
          <div className="loading">
            <div className="loading-icon">
              📦
            </div>

            <h3>
              Quarantine is empty
            </h3>

            <p>
              Dangerous emails that ZeroGuard quarantines will appear here.
            </p>
          </div>
        ) : (
          <div className="email-list">
            {quarantined.map(
              renderEmailCard
            )}
          </div>
        )}
      </section>
    )

  const pageTitle =
    activePage ===
    'Dashboard'
      ? 'Security Dashboard'
      : activePage ===
        'Check Message'
      ? 'Check a Suspicious Message'
      : activePage

  const navigationItems = [
    {
      name: 'Dashboard',
      icon: '▣'
    },
    {
      name: 'Check Message',
      icon: '🔍'
    },
    {
      name: 'Emails',
      icon: '✉'
    },
    {
      name: 'Threats',
      icon: '⚠'
    },
    {
      name: 'Quarantine',
      icon: '🛑'
    }
  ]

  // ============================================================
  // MAIN UI
  // ============================================================

  return (
    <div className="app">

      {loading && (
        <div className="top-loading-bar">
          <div className="top-loading-progress"></div>
        </div>
      )}

      <aside className="sidebar">

        <div className="logo">
          <div className="logo-icon">
            🛡️
          </div>

          <div>
            <h2>
              ZeroGuard
            </h2>

            <span>
              Email Security
            </span>
          </div>
        </div>

        <nav>
          {navigationItems.map(
            (item) => (
              <a
                key={item.name}
                className={
                  activePage ===
                  item.name
                    ? 'active'
                    : ''
                }
                onClick={() => {
                  setActivePage(
                    item.name
                  )

                  setExpandedEmail(
                    null
                  )

                  if (
                    item.name ===
                      'Quarantine' &&
                    connected
                  ) {
                    fetchQuarantinedEmails()
                  }
                }}
              >
                {item.icon}{' '}
                {item.name}
              </a>
            )
          )}
        </nav>

        {/* Sidebar Connection Card */}

        <div
          className={`system-status ${
            connected
              ? 'status-connected'
              : 'status-disconnected'
          }`}
        >
          <span
            className={`status-dot ${
              connected
                ? 'dot-active'
                : 'dot-inactive'
            }`}
          ></span>

          <div className="status-info">
            <strong>
              {connected
                ? 'Account Connected'
                : 'Not Connected'}
            </strong>

            <small className="status-email-preview">
              {connected
                ? userEmail ||
                  'Active session'
                : 'Connect to protect'}
            </small>
          </div>
        </div>
      </aside>

      <main className="main">

        <header className="header">

          <div>
            <div className="page-label">
              ZEROGUARD SECURITY
            </div>

            <h1>
              {pageTitle}
            </h1>

            <p>
              {activePage === 'Check Message'
                ? 'Analyze messages and URLs from WhatsApp, SMS, LinkedIn, and social media with AI protection.'
                : 'Monitor and analyze your incoming emails with AI protection.'}
            </p>
          </div>

          <div className="header-actions">

            {connected ? (
              <div className="user-profile-bar">

                <div
                  className="user-badge"
                  title={`Connected as ${userEmail}`}
                >
                  <span className="user-avatar-circle">
                    {userEmail
                      ? userEmail
                          .charAt(
                            0
                          )
                          .toUpperCase()
                      : '👤'}
                  </span>

                  <span className="user-email-text">
                    {userEmail}
                  </span>

                  <span className="online-indicator"></span>
                </div>

                <button
                  className="switch-btn"
                  onClick={handleSwitchAccount}
                  disabled={oauthLoading}
                  title="Connect a different Gmail account"
                >
                  Switch
                </button>

                <button
                  className="disconnect-btn"
                  onClick={
                    handleDisconnect
                  }
                  title="Disconnect your account"
                >
                  Disconnect
                </button>

              </div>
            ) : (
              <button
                className="connect-email-btn pulse-glow"
                onClick={
                  handleConnectEmail
                }
                id="connect-email-header-btn"
              >
                <span className="google-icon-badge">
                  G
                </span>

                Connect Your Email
              </button>
            )}

            <button
              className="refresh-btn"
              onClick={() =>
                loadDashboardData()
              }
              disabled={loading}
            >
              {loading
                ? '↻ Analyzing...'
                : '↻ Refresh'}
            </button>

          </div>
        </header>

        {successMessage && (
          <div className="success-banner">
            {successMessage}
          </div>
        )}

        {error && (
          <div className="error-message">

            <div
              style={{
                display:
                  'flex',
                justifyContent:
                  'space-between',
                alignItems:
                  'center'
              }}
            >
              <span>
                ⚠️ {error}
              </span>

              <button
                onClick={() =>
                  setError('')
                }
                style={{
                  background:
                    'transparent',
                  border: 'none',
                  color:
                    '#fca5a5',
                  cursor:
                    'pointer',
                  fontSize:
                    '14px',
                  fontWeight:
                    'bold'
                }}
              >
                ✕
              </button>
            </div>

            <br />

            <small>
              Ensure your FastAPI backend is running and that your Google Cloud Console OAuth redirect URIs are configured.
            </small>

          </div>
        )}

        {activePage ===
          'Dashboard' &&
          renderDashboard()}

        {activePage ===
          'Check Message' &&
          renderManualCheckCard(true)}

        {activePage ===
          'Emails' &&
          renderEmailsPage()}

        {activePage ===
          'Threats' &&
          renderThreatsPage()}

        {activePage ===
          'Quarantine' &&
          renderQuarantinePage()}

        <section className="protection">

          <div className="protection-icon">
            🛡️
          </div>

          <div>
            <h3>
              ZeroGuard is protecting your inbox
            </h3>

            <p>
              Incoming emails are automatically analyzed for phishing,
              suspicious links, impersonation, and social engineering
              threats using hybrid rule-based and Featherless AI analysis.
            </p>
          </div>

        </section>

      </main>
    </div>
  )
}

export default App