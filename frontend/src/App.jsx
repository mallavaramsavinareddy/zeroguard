import { useEffect, useState } from 'react'
import './App.css'

const API_URL =
  import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000'

function App() {
  const [emails, setEmails] = useState([])
  const [quarantined, setQuarantined] = useState([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [activePage, setActivePage] = useState('Dashboard')
  const [expandedEmail, setExpandedEmail] = useState(null)
  const [quarantiningId, setQuarantiningId] = useState(null)

  // ============================================================
  // FETCH INBOX EMAILS
  // ============================================================

  const fetchEmails = async () => {
    try {
      const response = await fetch(`${API_URL}/emails`)

      if (!response.ok) {
        throw new Error('Failed to fetch emails')
      }

      const data = await response.json()

      console.log('ZeroGuard API:', data)

      if (data.status === 'success') {
        setEmails(data.emails || [])
      } else {
        setError(data.error || 'Failed to load emails')
      }
    } catch (err) {
      console.error('Error fetching emails:', err)

      setError(
        'Unable to connect to ZeroGuard backend.'
      )
    }
  }

  // ============================================================
  // FETCH QUARANTINED EMAILS
  // ============================================================

  const fetchQuarantinedEmails = async () => {
    try {
      const response = await fetch(
        `${API_URL}/quarantine`
      )

      if (!response.ok) {
        throw new Error(
          'Failed to fetch quarantined emails'
        )
      }

      const data = await response.json()

      console.log(
        'ZeroGuard Quarantine API:',
        data
      )

      if (data.status === 'success') {
        setQuarantined(data.emails || [])
      }
    } catch (err) {
      console.error(
        'Error fetching quarantined emails:',
        err
      )
    }
  }

  // ============================================================
  // LOAD ALL DATA TOGETHER
  // ============================================================

  const loadDashboardData = async () => {
    try {
      setLoading(true)
      setError('')

      await Promise.all([
        fetchEmails(),
        fetchQuarantinedEmails()
      ])
    } finally {
      setLoading(false)
    }
  }

  // ============================================================
  // QUARANTINE EMAIL
  // ============================================================

  const quarantineEmail = async (email) => {
    try {
      setQuarantiningId(email.id)

      const response = await fetch(
        `${API_URL}/quarantine/${email.id}`,
        {
          method: 'POST'
        }
      )

      const data = await response.json()

      console.log('Quarantine response:', data)

      if (data.status === 'success') {
        setEmails((previousEmails) =>
          previousEmails.filter(
            (item) => item.id !== email.id
          )
        )

        await fetchQuarantinedEmails()

        setExpandedEmail(null)

        alert('🚨 Email moved to quarantine!')
      } else {
        alert(
          `Failed to quarantine email: ${
            data.error || 'Unknown error'
          }`
        )
      }
    } catch (err) {
      console.error('Quarantine error:', err)

      alert(
        'Unable to connect to ZeroGuard backend.'
      )
    } finally {
      setQuarantiningId(null)
    }
  }

  // ============================================================
  // INITIAL LOAD
  // ============================================================

  useEffect(() => {
    loadDashboardData()
  }, [])

  // ============================================================
  // STATISTICS
  // ============================================================

  const allEmailsMap = new Map()

  emails.forEach((email) => {
    allEmailsMap.set(email.id, email)
  })

  quarantined.forEach((email) => {
    allEmailsMap.set(email.id, email)
  })

  const allAnalyzedEmails =
    Array.from(allEmailsMap.values())

  const safeCount = allAnalyzedEmails.filter(
    (email) =>
      email.security?.risk_level?.toUpperCase() ===
      'LOW'
  ).length

  const suspiciousCount = allAnalyzedEmails.filter(
    (email) => {
      const level =
        email.security?.risk_level?.toUpperCase()

      return level === 'MEDIUM' || level === 'HIGH'
    }
  ).length

  const dangerousCount = allAnalyzedEmails.filter(
    (email) =>
      email.security?.risk_level?.toUpperCase() ===
      'CRITICAL'
  ).length

  const quarantinedCount = quarantined.length

  const totalEmails = allAnalyzedEmails.length

  const totalThreats = allAnalyzedEmails.filter(
    (email) => {
      const level =
        email.security?.risk_level?.toUpperCase()

      return (
        level === 'MEDIUM' ||
        level === 'HIGH' ||
        level === 'CRITICAL'
      )
    }
  ).length

  const protectionScore =
    totalEmails > 0
      ? Math.round((safeCount / totalEmails) * 100)
      : 0

  // ============================================================
  // EMAIL CARD
  // ============================================================

  const renderEmailCard = (email, index) => {
    const riskLevel =
      email.security?.risk_level?.toUpperCase() ||
      'QUARANTINED'

    const riskScore =
      email.security?.risk_score ?? 0

    const reasons =
      email.security?.reasons || []

    const intent =
      email.security?.intent || {}

    const aiAnalysis =
      email.security?.ai_analysis || {}

    const attackerIntent =
      intent.attacker_intent || 'Not determined'

    const expectedUserAction =
      intent.expected_user_action || 'Not determined'

    const potentialConsequence =
      intent.potential_consequence || 'Not determined'

    const recommendedDefense =
      intent.recommended_defense || 'Manual review'

    const isExpanded =
      expandedEmail === email.id

    const isQuarantining =
      quarantiningId === email.id

    const toggleDetails = () => {
      setExpandedEmail(
        isExpanded ? null : email.id
      )
    }

    return (
      <div
        className={`email-card ${riskLevel.toLowerCase()}`}
        key={email.id || index}
      >
        <div
          className="email-main"
          onClick={toggleDetails}
        >
          <div className="email-avatar">
            {email.sender
              ? email.sender.charAt(0).toUpperCase()
              : '?'}
          </div>

          <div className="email-content">
            <div className="email-title-row">
              <h3>
                {email.subject || 'No Subject'}
              </h3>

              <span
                className={`risk-badge ${riskLevel.toLowerCase()}`}
              >
                {riskLevel}
              </span>
            </div>

            <p className="sender">
              {email.sender || 'Unknown Sender'}
            </p>

            <p className="email-preview">
              {email.body
                ? email.body
                    .substring(0, 120)
                    .replace(/\n/g, ' ')
                : 'No email content available'}

              {email.body?.length > 120 ? '...' : ''}
            </p>
          </div>
        </div>

        <div className="email-actions">
          <div className="score">
            <span>Risk Score</span>
            <strong>{riskScore}/100</strong>
          </div>

          {riskLevel === 'CRITICAL' && (
            <button
              className="quarantine-btn"
              disabled={isQuarantining}
              onClick={(event) => {
                event.stopPropagation()
                quarantineEmail(email)
              }}
            >
              {isQuarantining
                ? 'Moving...'
                : '🛑 Quarantine'}
            </button>
          )}

          <button
            className="details-btn"
            onClick={(event) => {
              event.stopPropagation()
              toggleDetails()
            }}
          >
            {isExpanded ? 'Hide' : 'Details'}
          </button>
        </div>

        {isExpanded && (
          <div className="threat-details">
            <h4>🔍 Security Analysis</h4>

            <div className="risk-summary">
              <div className="risk-summary-item">
                <span>Risk Level</span>

                <strong
                  className={`risk-text ${riskLevel.toLowerCase()}`}
                >
                  {riskLevel}
                </strong>
              </div>

              <div className="risk-summary-item">
                <span>Risk Score</span>
                <strong>{riskScore}/100</strong>
              </div>

              <div className="risk-summary-item">
                <span>AI Status</span>

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

                  <h3>🧠 IntentShield</h3>
                </div>

                <span className="intent-status">
                  {aiAnalysis.available
                    ? '● AI ACTIVE'
                    : 'RULE-BASED'}
                </span>
              </div>

              <p className="intent-description">
                ZeroGuard predicts what the attacker
                wants the user to do, what could happen,
                and how the threat should be handled.
              </p>

              <div className="intent-grid">
                <div className="intent-item">
                  <div className="intent-icon">🎯</div>

                  <div>
                    <span>Attacker Intent</span>
                    <strong>{attackerIntent}</strong>
                  </div>
                </div>

                <div className="intent-item">
                  <div className="intent-icon">👆</div>

                  <div>
                    <span>Expected User Action</span>
                    <strong>{expectedUserAction}</strong>
                  </div>
                </div>

                <div className="intent-item">
                  <div className="intent-icon">💥</div>

                  <div>
                    <span>Potential Consequence</span>
                    <strong>{potentialConsequence}</strong>
                  </div>
                </div>

                <div className="intent-item">
                  <div className="intent-icon">🛡️</div>

                  <div>
                    <span>Recommended Defense</span>
                    <strong>{recommendedDefense}</strong>
                  </div>
                </div>
              </div>
            </div>

            <div className="analysis-reasons">
              <h4>⚠️ Detection Reasons</h4>

              {reasons.length > 0 ? (
                <ul>
                  {reasons.map((reason, reasonIndex) => (
                    <li key={reasonIndex}>
                      {reason}
                    </li>
                  ))}
                </ul>
              ) : (
                <p className="safe-message">
                  ✓ No security threats detected.
                </p>
              )}
            </div>

            {email.links?.length > 0 && (
              <div className="links-section">
                <strong>🔗 Links detected:</strong>

                {email.links.map((link, linkIndex) => (
                  <div
                    key={linkIndex}
                    className="detected-link"
                  >
                    {link}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    )
  }

  // ============================================================
  // DASHBOARD PAGE
  // ============================================================

  const renderDashboard = () => (
    <>
      <section className="stats">
        <div className="stat-card">
          <div className="stat-icon">📧</div>

          <div>
            <span>Total Emails</span>
            <strong>{totalEmails}</strong>
          </div>
        </div>

        <div className="stat-card safe-card">
          <div className="stat-icon">✓</div>

          <div>
            <span>Safe</span>
            <strong>{safeCount}</strong>
          </div>
        </div>

        <div className="stat-card warning-card">
          <div className="stat-icon">⚠</div>

          <div>
            <span>Suspicious</span>
            <strong>{suspiciousCount}</strong>
          </div>
        </div>

        <div className="stat-card danger-card">
          <div className="stat-icon">!</div>

          <div>
            <span>Dangerous</span>
            <strong>{dangerousCount}</strong>
          </div>
        </div>

        <div className="stat-card quarantine-card">
          <div className="stat-icon">🛡️</div>

          <div>
            <span>Quarantined</span>
            <strong>{quarantinedCount}</strong>
          </div>
        </div>
      </section>

      <section className="security-overview">
        <div>
          <span>Security Status</span>

          <h2>
            {totalThreats === 0
              ? '✓ Your inbox is secure'
              : `⚠ ${totalThreats} threat${
                  totalThreats > 1 ? 's' : ''
                } detected`}
          </h2>
        </div>

        <div className="protection-score">
          <strong>{protectionScore}%</strong>
          <span>Safe Emails</span>
        </div>
      </section>

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
          <h2>Recent Emails</h2>

          <p>
            Security analysis of incoming messages
          </p>
        </div>

        <button
          className="view-btn"
          onClick={() => setActivePage('Emails')}
        >
          View All →
        </button>
      </div>

      {/* Show full loading screen only during the first load */}
      {loading && emails.length === 0 && (
        <div className="loading">
          <div className="loading-icon">🛡️</div>

          <h3>Analyzing your inbox...</h3>

          <p>
            ZeroGuard is checking incoming emails
            for threats.
          </p>
        </div>
      )}

      {!loading &&
        !error &&
        emails.length === 0 && (
          <div className="loading">
            <div className="loading-icon">📭</div>

            <h3>No emails found</h3>

            <p>
              No emails are available for security
              analysis.
            </p>
          </div>
        )}

      {/* Keep existing emails visible while refreshing */}
      {emails.length > 0 && (
        <div className="email-list">
          {emails
            .slice(0, 5)
            .map(renderEmailCard)}
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
          <h2>✉ All Emails</h2>

          <p>
            Complete security analysis of your inbox
          </p>
        </div>
      </div>

      {/* Show loading screen only if there are no old emails */}
      {loading && emails.length === 0 && (
        <div className="loading">
          <div className="loading-icon">🛡️</div>

          <h3>Analyzing your inbox...</h3>

          <p>
            ZeroGuard is checking incoming emails
            for threats.
          </p>
        </div>
      )}

      {!loading &&
        !error &&
        emails.length === 0 && (
          <div className="loading">
            <div className="loading-icon">📭</div>

            <h3>No emails available</h3>
          </div>
        )}

      {/* Keep old emails visible during refresh */}
      {emails.length > 0 && (
        <div className="email-list">
          {emails.map(renderEmailCard)}
        </div>
      )}
    </section>
  )

  // ============================================================
  // THREATS PAGE
  // ============================================================

  const renderThreatsPage = () => {
    const threatsMap = new Map()

    emails.forEach((email) => {
      const level =
        email.security?.risk_level?.toUpperCase()

      if (
        level === 'MEDIUM' ||
        level === 'HIGH' ||
        level === 'CRITICAL'
      ) {
        threatsMap.set(email.id, email)
      }
    })

    quarantined.forEach((email) => {
      const level =
        email.security?.risk_level?.toUpperCase()

      if (
        level === 'MEDIUM' ||
        level === 'HIGH' ||
        level === 'CRITICAL'
      ) {
        threatsMap.set(email.id, email)
      }
    })

    const threats = Array.from(threatsMap.values())

    return (
      <section className="email-section">
        <div className="section-header">
          <div>
            <h2>🚨 Detected Threats</h2>

            <p>
              Emails requiring your attention
            </p>
          </div>

          <span className="quarantine-count">
            {threats.length} detected
          </span>
        </div>

        {threats.length === 0 ? (
          <div className="loading">
            <div className="loading-icon">✓</div>

            <h3>No threats detected</h3>

            <p>
              ZeroGuard hasn't detected any
              suspicious emails.
            </p>
          </div>
        ) : (
          <div className="email-list">
            {threats.map(renderEmailCard)}
          </div>
        )}
      </section>
    )
  }

  // ============================================================
  // QUARANTINE PAGE
  // ============================================================

  const renderQuarantinePage = () => (
    <section className="email-section">
      <div className="section-header">
        <div>
          <h2>🛑 Quarantine</h2>

          <p>
            Emails isolated by ZeroGuard
          </p>
        </div>

        <span className="quarantine-count">
          {quarantinedCount} isolated
        </span>
      </div>

      {quarantined.length === 0 ? (
        <div className="loading">
          <div className="loading-icon">📦</div>

          <h3>Quarantine is empty</h3>

          <p>
            Dangerous emails that ZeroGuard
            quarantines will appear here.
          </p>
        </div>
      ) : (
        <div className="email-list">
          {quarantined.map(renderEmailCard)}
        </div>
      )}
    </section>
  )

  const pageTitle =
    activePage === 'Dashboard'
      ? 'Security Dashboard'
      : activePage

  const navigationItems = [
    {
      name: 'Dashboard',
      icon: '▣'
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
      icon: '▣'
    }
  ]

  // ============================================================
  // MAIN UI
  // ============================================================

  return (
    <div className="app">

      {/* Thin loading bar shown at the top during refresh */}
      {loading && (
        <div className="top-loading-bar">
          <div className="top-loading-progress"></div>
        </div>
      )}

      <aside className="sidebar">
        <div className="logo">
          <div className="logo-icon">🛡️</div>

          <div>
            <h2>ZeroGuard</h2>
            <span>Email Security</span>
          </div>
        </div>

        <nav>
          {navigationItems.map((item) => (
            <a
              key={item.name}
              className={
                activePage === item.name
                  ? 'active'
                  : ''
              }
              onClick={() => {
                setActivePage(item.name)
                setExpandedEmail(null)

                if (item.name === 'Quarantine') {
                  fetchQuarantinedEmails()
                }
              }}
            >
              {item.icon} {item.name}
            </a>
          ))}
        </nav>

        <div className="system-status">
          <span className="status-dot"></span>

          <div>
            <strong>System Active</strong>
            <small>Protection enabled</small>
          </div>
        </div>
      </aside>

      <main className="main">
        <header className="header">
          <div>
            <div className="page-label">
              ZEROGUARD SECURITY
            </div>

            <h1>{pageTitle}</h1>

            <p>
              Monitor and analyze your incoming
              emails.
            </p>
          </div>

          <button
            className="refresh-btn"
            onClick={loadDashboardData}
            disabled={loading}
          >
            {loading
              ? '↻ Analyzing...'
              : '↻ Refresh Emails'}
          </button>
        </header>

        {error && (
          <div className="error-message">
            ⚠️ {error}

            <br />

            <small>
              Make sure your FastAPI backend is
              running on port 8000.
            </small>
          </div>
        )}

        {activePage === 'Dashboard' &&
          renderDashboard()}

        {activePage === 'Emails' &&
          renderEmailsPage()}

        {activePage === 'Threats' &&
          renderThreatsPage()}

        {activePage === 'Quarantine' &&
          renderQuarantinePage()}

        <section className="protection">
          <div className="protection-icon">🛡️</div>

          <div>
            <h3>
              ZeroGuard is protecting your inbox
            </h3>

            <p>
              Incoming emails are automatically
              analyzed for phishing, suspicious
              links, impersonation and social
              engineering threats.
            </p>
          </div>
        </section>
      </main>
    </div>
  )
}

export default App