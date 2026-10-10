import React, { useState, useRef, useEffect } from 'react';
import { Search, Bell, Sun, Moon, User, Shield, RefreshCw, Clock, FileText, LogOut, AlertTriangle, CheckCircle, Info, Github, Filter, Download, Play, GitBranch, LayoutDashboard, Target, Sparkles, History, Plus } from 'lucide-react';
import { useGoogleLogin, googleLogout, GoogleLogin } from '@react-oauth/google';
import './CodeGuard.css';

// Main App Component with MongoDB & Google Auth integration
const CodeGuardApp = () => {
  const [currentPage, setCurrentPage] = useState('landing');
  const [darkMode, setDarkMode] = useState(true);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('codeguard_token'));

  // Scan state
  const [vulnerabilities, setVulnerabilities] = useState([]);
  const [markedCode, setMarkedCode] = useState('');
  const [isScanning, setIsScanning] = useState(false);
  const [selectedVulnerability, setSelectedVulnerability] = useState(null);
  const [fixedCode, setFixedCode] = useState('');

  // Live scan progress
  const [scanProgress, setScanProgress] = useState(0);
  const [scanStep, setScanStep] = useState(0);
  const [scanComplete, setScanComplete] = useState(false);
  const [scanLogs, setScanLogs] = useState([]);
  const [totalFiles, setTotalFiles] = useState(0);
  const [scanningRepo, setScanningRepo] = useState('');
  const [viewingScanId, setViewingScanId] = useState(null);
  const eventSourceRef = useRef(null);

  // Auth flow
  useEffect(() => {
    const savedUser = localStorage.getItem('codeguard_user');
    const savedToken = localStorage.getItem('codeguard_token');
    console.log("Auth Init:", { hasUser: !!savedUser, hasToken: !!savedToken });
    if (savedUser) setUser(JSON.parse(savedUser));
    if (savedToken) setToken(savedToken);
  }, []);

  const handleLoginSuccess = async (googleResponse) => {
    try {
      console.log("Google response received, verifying with backend...");
      const res = await fetch('/api/auth/google', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ token: googleResponse.credential })
      });
      console.log("Backend auth response status:", res.status);
      const data = await res.json();
      if (data.token) {
        setToken(data.token);
        setUser(data.user);
        localStorage.setItem('codeguard_token', data.token);
        localStorage.setItem('codeguard_user', JSON.stringify(data.user));
        setCurrentPage('dashboard');
        console.log("Login successful, redirected to dashboard.");
      } else {
        console.error("Backend login failed: No token in response", data);
      }
    } catch (error) {
      console.error('Login failed during backend handshake:', error);
    }
  };

  const logout = () => {
    googleLogout();
    setToken(null);
    setUser(null);
    localStorage.removeItem('codeguard_token');
    localStorage.removeItem('codeguard_user');
    setCurrentPage('landing');
  };

  const authenticatedFetch = async (url, options = {}) => {
    const headers = { ...options.headers, 'Authorization': `Bearer ${token}` };
    return fetch(url, { ...options, headers });
  };

  const handleViewDetails = async (v) => {
    try {
      console.log("handleViewDetails - Selection Triggered:", v.title);
      setSelectedVulnerability(v);
      setFixedCode(''); // Reset for new fix content
      // If we have a viewingScanId, fetch hydrated details (includes code snippets)
      if (viewingScanId) {
        const res = await authenticatedFetch(`/api/scan/${viewingScanId}/vulnerability/${v.id || v._id}`);
        if (res.ok) {
          const data = await res.json();
          console.log("handleViewDetails - Data Hydrated:", data.title);
          setSelectedVulnerability(prev => ({ ...prev, ...data }));
        }
      }
    } catch (err) {
      console.error('Error loading vuln details:', err);
    }
  };

  const loadHistoricalScan = async (scan) => {
    try {
      const res = await authenticatedFetch(`/api/scan/${scan.id}`);
      const data = await res.json();
      if (data.vulnerabilities) {
        setVulnerabilities(data.vulnerabilities);
      } else {
        setVulnerabilities([]);
      }
      setScanningRepo(scan.repo_url || '');
      setViewingScanId(scan.id);
      setCurrentPage('scanResults');
    } catch (err) {
      console.error('Failed to load historical scan:', err);
      // Navigate anyway, show empty state
      setScanningRepo(scan.repo_url || '');
      setVulnerabilities([]);
      setCurrentPage('scanResults');
    }
  };

  const startScan = (repoUrl) => {
    if (!repoUrl.trim()) return;
    setIsScanning(true);
    setScanProgress(0);
    setScanStep(0);
    setScanComplete(false);
    setScanningRepo(repoUrl);
    setScanLogs([]);
    setVulnerabilities([]);
    setTotalFiles(0);
    setCurrentPage('scanProgress');

    if (eventSourceRef.current) eventSourceRef.current.close();
    // Pass token in URL for SSE authentication
    const es = new EventSource(`/api/scan/stream?repo_url=${encodeURIComponent(repoUrl)}&token=${token}`);
    eventSourceRef.current = es;

    const ts = () => new Date().toLocaleTimeString('en-US', { hour12: false });

    es.onerror = (err) => {
      console.error('SSE Error:', err);
      
      // If the connection was already closed or the error is terminal
      if (es.readyState === EventSource.CLOSED) {
        setScanLogs(prev => [...prev, {
          level: 'error',
          message: '❌ Connection to scan engine lost. The scan may still be running on the server, but the live view was disconnected.',
          timestamp: ts()
        }]);
        setIsScanning(false);
        es.close();
      } else {
        // Transient error, EventSource will auto-reconnect
        setScanLogs(prev => [...prev, {
          level: 'warning',
          message: '⚠️ Connection interrupted. Trying to reconnect...',
          timestamp: ts()
        }]);
      }
    };

    es.onmessage = (e) => {
      try {
        const msg = JSON.parse(e.data);
        if (msg.type === 'log') {
          setScanLogs(prev => [...prev, { level: msg.level, message: msg.message, timestamp: ts() }]);
        } else if (msg.type === 'progress') {
          setScanProgress(msg.value);
          if (msg.step !== undefined) setScanStep(msg.step);
        } else if (msg.type === 'total_files') {
          setTotalFiles(msg.total);
        } else if (msg.type === 'vulnerabilities') {
          if (msg.items) setVulnerabilities(prev => [...prev, ...msg.items]);
        } else if (msg.type === 'done') {
          setScanProgress(100);
          setScanStep(4);
          setScanComplete(true);
          setIsScanning(false);
          if (msg.scan_id) setViewingScanId(msg.scan_id);
          es.close();
        } else if (msg.type === 'error') {
          setScanLogs(prev => [...prev, { level: 'error', message: msg.message, timestamp: ts() }]);
          setIsScanning(false);
          es.close();
        }
      } catch (err) { console.error('SSE parse error:', err); }
    };
  };

  // UI Components
  const Sidebar = () => (
    <div className={`sidebar ${darkMode ? 'dark' : 'light'}`}>
      <div className="sidebar-header">
        <div className="logo"><Shield className="logo-icon" /><span className="logo-text">CodeGuard</span></div>
      </div>
      <nav className="sidebar-nav">
        {[
          { id: 'dashboard', label: 'Dashboard', icon: <LayoutDashboard size={20} /> },
          { id: 'newScan', label: 'New Scan', icon: <Target size={20} /> },
          { id: 'history', label: 'Scan History', icon: <History size={20} /> },
          { id: 'reports', label: 'Reports', icon: <FileText size={20} /> },
          { id: 'remediation', label: 'Remediation', icon: <Sparkles size={20} /> }
        ].map(item => (
          <button key={item.id} onClick={() => setCurrentPage(item.id)} className={`nav-item ${currentPage === item.id ? 'active' : ''}`}>
             {item.icon} <span>{item.label}</span>
          </button>
        ))}
      </nav>
      <div className="sidebar-footer">
        <button onClick={logout} className="logout-btn"><LogOut size={20} /> <span>Logout</span></button>
      </div>
    </div>
  );

  const TopBar = () => (
    <div className={`topbar ${darkMode ? 'dark' : 'light'}`}>
      <div className="search-box"><Search className="search-icon" size={20} /><input type="text" placeholder="Search..." className="search-input" /></div>
      <div className="topbar-actions">
        <button onClick={() => setDarkMode(!darkMode)} className="icon-btn">{darkMode ? <Sun size={20} /> : <Moon size={20} />}</button>
        <div className="user-profile">
            {user?.picture ? (
                <img src={user.picture} alt="Avatar" className="profile-img" />
            ) : (
                <div className="profile-img-placeholder"><User size={20} /></div>
            )}
            <span className="user-name">{user?.name || 'User'}</span>
        </div>
      </div>
    </div>
  );

  const Dashboard = () => {
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);

    const fetchScans = () => {
      if (token) {
        setLoading(true);
        authenticatedFetch('/api/scans')
          .then(r => r.json())
          .then(data => { setScans(Array.isArray(data) ? data : []); setLoading(false); })
          .catch(() => setLoading(false));
      } else {
        setLoading(false);
      }
    };

    useEffect(() => {
      fetchScans();
    }, [token]);

    const handleReset = async () => {
      if (window.confirm("⚠️ ARE YOU SURE? This will permanently delete ALL your scan history. This action cannot be undone.")) {
        try {
          const res = await authenticatedFetch('/api/scans/reset', { method: 'POST' });
          if (res.ok) {
            setScans([]);
            console.log("Scan history cleared successfully.");
          }
        } catch (err) {
          console.error("Failed to reset scans:", err);
        }
      }
    };

    const totalScans = scans.length;
    const criticalIssues = scans.reduce((acc, s) => acc + (s.severities?.critical || 0), 0);
    const resolvedIssues = scans.reduce((acc, s) => acc + (s.resolved_count || 0), 0);
    const pendingJobs = scans.filter(s => s.status?.toLowerCase() === 'in progress' || s.status?.toLowerCase() === 'running').length;

    const getSeverityBadge = (scan) => {
      const sevs = scan.severities || {};
      if (sevs.critical > 0) return 'critical';
      if (sevs.high > 0) return 'high';
      if (sevs.medium > 0) return 'medium';
      if (sevs.low > 0) return 'low';
      return null;
    };

    const getRiskScore = (scan) => {
      const count = scan.vulnerability_count || 0;
      if (count === 0) return '–';
      return Math.min(10, (count * 1.2)).toFixed(1);
    };

    const themeClass = darkMode ? 'dark' : 'light';

    return (
      <div className={`dash-page ${themeClass}`}>
        <div className="dash-header" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
          <div>
            <h1 className="dash-title">Dashboard</h1>
            <p className="dash-subtitle">Overview of your security scans</p>
          </div>
          <button 
            onClick={handleReset}
            className="btn-reset-history"
            style={{
              padding: '0.6rem 1.2rem',
              borderRadius: '8px',
              border: '1px solid #ef4444',
              background: 'transparent',
              color: '#ef4444',
              fontSize: '0.85rem',
              fontWeight: '600',
              cursor: 'pointer',
              transition: 'all 0.2s ease'
            }}
            onMouseOver={(e) => { e.target.style.background = '#ef4444'; e.target.style.color = '#fff'; }}
            onMouseOut={(e) => { e.target.style.background = 'transparent'; e.target.style.color = '#ef4444'; }}
          >
            Reset History
          </button>
        </div>

        {/* Stat Cards */}
        <div className="dash-stats-grid">
          <div className={`dash-stat-card ${themeClass}`}>
            <div className="dash-stat-top">
              <div className="dash-stat-icon blue"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg></div>
              <span className="dash-stat-change positive">+{totalScans > 0 ? totalScans : 0}</span>
            </div>
            <div className="dash-stat-value">{loading ? '–' : totalScans}</div>
            <div className="dash-stat-label">Total Scans</div>
          </div>

          <div className={`dash-stat-card ${themeClass}`}>
            <div className="dash-stat-top">
              <div className="dash-stat-icon red"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg></div>
              <span className="dash-stat-change negative">{criticalIssues > 0 ? `-${criticalIssues}%` : '–'}</span>
            </div>
            <div className="dash-stat-value">{loading ? '–' : criticalIssues}</div>
            <div className="dash-stat-label">Critical Issues</div>
          </div>

          <div className={`dash-stat-card ${themeClass}`}>
            <div className="dash-stat-top">
              <div className="dash-stat-icon green"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg></div>
              <span className="dash-stat-change positive">+{resolvedIssues > 0 ? '24%' : '0%'}</span>
            </div>
            <div className="dash-stat-value">{loading ? '–' : resolvedIssues}</div>
            <div className="dash-stat-label">Resolved Issues</div>
          </div>

          <div className={`dash-stat-card ${themeClass}`}>
            <div className="dash-stat-top">
              <div className="dash-stat-icon orange"><svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/></svg></div>
              <span className="dash-stat-info">{pendingJobs > 0 ? `${pendingJobs} active` : 'None'}</span>
            </div>
            <div className="dash-stat-value">{loading ? '–' : pendingJobs}</div>
            <div className="dash-stat-label">Pending Jobs</div>
          </div>
        </div>

        {/* Recent Scans Table */}
        <div className={`dash-table-card ${themeClass}`}>
          <h2 className="dash-section-title">Recent Scans</h2>
          <div className="dash-table-wrapper">
            <table className="dash-table">
              <thead>
                <tr>
                  <th>Repo Name</th>
                  <th>Date</th>
                  <th>Status</th>
                  <th>Severity</th>
                  <th>Risk Score</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan="6" className="dash-empty">Loading scans...</td></tr>
                ) : scans.length === 0 ? (
                  <tr><td colSpan="6" className="dash-empty">No scans yet. <button onClick={() => setCurrentPage('newScan')} className="dash-empty-link">Start your first scan →</button></td></tr>
                ) : (
                  scans.slice(0, 10).map((s, i) => {
                    const sev = getSeverityBadge(s);
                    const statusClass = s.status?.toLowerCase().replace(' ', '-');
                    return (
                      <tr key={s.id || i}>
                        <td className="dash-repo-name">{s.repo_url?.replace('https://github.com/', '') || '–'}</td>
                        <td className="dash-date">{s.date ? new Date(s.date).toISOString().split('T')[0] : '–'}</td>
                        <td><span className={`dash-status-badge ${statusClass}`}>{s.status || '–'}</span></td>
                        <td>{sev ? <span className={`dash-severity-badge ${sev}`}>{sev.charAt(0).toUpperCase() + sev.slice(1)}</span> : <span className="dash-severity-none">–</span>}</td>
                        <td className="dash-risk-score">{getRiskScore(s)}</td>
                        <td><button className="dash-view-btn" onClick={() => loadHistoricalScan(s)}>View Details</button></td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  const ScanHistoryPage = () => {
    const [scans, setScans] = useState([]);
    const [loading, setLoading] = useState(true);
    const themeClass = darkMode ? 'dark' : 'light';

    useEffect(() => {
      if (token) {
        authenticatedFetch('/api/scans')
          .then(r => r.json())
          .then(data => { setScans(Array.isArray(data) ? data : []); setLoading(false); })
          .catch(() => setLoading(false));
      } else {
        setLoading(false);
      }
    }, [token]);

    const getRiskLevel = (count) => {
      if (count === 0) return 'Safe';
      if (count < 5) return 'Low';
      if (count < 15) return 'Medium';
      return 'High';
    };

    return (
      <div className={`scan-history-page ${themeClass}`}>
        <div className="history-header-row">
          <div className="history-title-group">
            <h1 className="history-page-title">Scan History</h1>
            <p className="history-page-subtitle">Manage and review your past security audits</p>
          </div>
          <div className="history-actions">
            <button onClick={() => setCurrentPage('newScan')} className="btn-new-scan-history">
              <Plus size={16} /> New Scan
            </button>
          </div>
        </div>

        <div className={`history-list-card ${themeClass}`}>
          <div className="history-table-wrapper">
            <table className="history-modern-table">
              <thead>
                <tr>
                  <th>Repository</th>
                  <th>Scan Date</th>
                  <th>Status</th>
                  <th>Findings</th>
                  <th>Risk Level</th>
                  <th className="text-right">Actions</th>
                </tr>
              </thead>
              <tbody>
                {loading ? (
                  <tr><td colSpan="6" className="text-center py-10">Loading history...</td></tr>
                ) : scans.length === 0 ? (
                  <tr><td colSpan="6" className="text-center py-10">No scans found.</td></tr>
                ) : (
                  scans.map((s, i) => (
                    <tr key={s.id || i} className="history-row">
                      <td className="repo-cell">
                        <div className="repo-info-box">
                          <Github size={16} className="icon-muted" />
                          <span className="repo-name-text">{s.repo_url?.split('/').pop() || 'Untitled'}</span>
                        </div>
                        <div className="repo-url-sub">{s.repo_url?.replace('https://github.com/', '')}</div>
                      </td>
                      <td className="date-cell">{new Date(s.date).toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })}</td>
                      <td>
                        <span className={`status-badge-modern ${s.status?.toLowerCase().replace(' ', '-')}`}>
                          {s.status}
                        </span>
                      </td>
                      <td className="findings-cell">
                        <span className="findings-count">{s.vulnerability_count || 0}</span>
                        <span className="findings-label"> issues</span>
                      </td>
                      <td>
                        <span className={`risk-badge-modern ${getRiskLevel(s.vulnerability_count || 0).toLowerCase()}`}>
                          {getRiskLevel(s.vulnerability_count || 0)}
                        </span>
                      </td>
                      <td className="text-right row-actions">
                        <button className="icon-btn-history" onClick={() => loadHistoricalScan(s)} title="View Results">
                          <LayoutDashboard size={18} />
                        </button>
                        <button className="icon-btn-history" title="Download PDF" onClick={async () => {
                          const res = await authenticatedFetch(`/api/scan/${s.id}`);
                          const data = await res.json();
                          setVulnerabilities(data.vulnerabilities || []);
                          setScanningRepo(s.repo_url); 
                          setCurrentPage('scanResults'); 
                          setTimeout(() => window.print(), 800);
                        }}>
                          <Download size={18} />
                        </button>
                        <button className="icon-btn-history" title="Export JSON" onClick={() => {
                          const blob = new Blob([JSON.stringify(s, null, 2)], { type: 'application/json' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a'); a.href = url; a.download = `scan-${s.id}.json`; a.click();
                        }}>
                          <FileText size={18} />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    );
  };

  const LoginPage = () => {
    const login = useGoogleLogin({
      onSuccess: tokenResponse => {
        console.log("Google login successful, sending access token to backend...");
        handleLoginSuccess({ credential: tokenResponse.access_token });
      },
      onError: error => console.error('Login Failed:', error),
    });

    return (
      <div className={`auth-page ${darkMode ? 'dark' : 'light'}`}>
        <div className="auth-container">
          <div className="auth-header">
              <Shield className="logo-icon-large" />
              <h1 className="logo-text-large">CodeGuard</h1>
              <p className="auth-subtitle">Enterprise Security Pipeline</p>
          </div>
          <div className="auth-card">
            <h2 className="auth-title">Welcome Back</h2>
            <p className="auth-prompt">Sign in to your security dashboard</p>
            <div className="google-login-wrapper">
              <button 
                onClick={() => login()} 
                className="google-btn"
              >
                <svg viewBox="0 0 24 24" width="18" height="18" xmlns="http://www.w3.org/2000/svg">
                  <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
                  <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                  <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
                  <path d="M12 5.38c1.62 0 3.06.56 4.21 1.66l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 12-4.53z" fill="#EA4335"/>
                </svg>
                <span>Sign in with Google</span>
              </button>
            </div>
            <div className="auth-footer">
                <p>New to CodeGuard? <span className="link">Request access</span></p>
            </div>
          </div>
        </div>
      </div>
    );
  };

  const ScanProgressPage = () => {
    const logsEndRef = useRef(null);
    useEffect(() => logsEndRef.current?.scrollIntoView({ behavior: 'smooth' }), [scanLogs]);

    const themeClass = darkMode ? 'dark' : 'light';
    const repoLabel = scanningRepo.replace('https://github.com/', '');

    const STEPS = [
      { label: 'Fetch repo', icon: '⬇' },
      { label: 'Analyze files', icon: '🔍' },
      { label: 'Detect issues', icon: '🔬' },
      { label: 'Generate fixes', icon: '🛠' },
      { label: 'Create report', icon: '📄' },
    ];

    const getStepState = (i) => {
      if (scanComplete) return 'done';
      if (i < scanStep) return 'done';
      if (i === scanStep) return 'active';
      return 'pending';
    };

    return (
      <div className={`scan-progress-page ${themeClass}`}>
        <div className="sp-header">
          <div className="sp-header-left">
            <h1 className="sp-title">Scan Progress</h1>
            <p className="sp-subtitle">Scanning: <span className="sp-repo-highlight">{repoLabel || scanningRepo}</span></p>
          </div>
          <div className="sp-header-right">
            <div className="sp-status-actions">
              {!scanComplete ? (
                <span className="sp-pulse-status">
                  <span className="sp-pulse-dot"></span> RUNNING
                </span>
              ) : (
                <span className="sp-completed-status">
                  <CheckCircle size={16} /> COMPLETED
                </span>
              )}
              {!scanComplete && (
                <button className="sp-cancel-btn" onClick={() => { eventSourceRef.current?.close(); setIsScanning(false); setCurrentPage('newScan'); }}>
                  Cancel
                </button>
              )}
            </div>
          </div>
        </div>

        {/* Stepper */}
        <div className={`sp-card ${themeClass}`}>
          <div className="sp-stepper">
            {STEPS.map((step, i) => {
              const state = getStepState(i);
              return (
                <div key={i} className={`sp-step-group`}>
                  <div className={`sp-step-node ${state}`}>
                    {state === 'done'
                      ? <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="3"><polyline points="20 6 9 17 4 12"/></svg>
                      : state === 'active'
                        ? <span className="sp-step-spinner"></span>
                        : <span className="sp-step-dot"></span>
                    }
                  </div>
                  {i < STEPS.length - 1 && <div className={`sp-step-line ${state === 'done' ? 'done' : ''}`}></div>}
                  <div className={`sp-step-label ${state}`}>{step.label}</div>
                </div>
              );
            })}
          </div>

          {/* Progress Bar */}
          <div className="sp-progress-area">
            <div className="sp-progress-info">
              <span>Overall Progress</span>
              <span className="sp-pct">{scanProgress}%</span>
            </div>
            <div className="sp-progress-track">
              <div
                className="sp-progress-fill"
                style={{ width: `${scanProgress}%`, transition: 'width 0.5s ease' }}
              ></div>
            </div>
          </div>
        </div>

        {/* Live Logs */}
        <div className={`sp-logs-card ${themeClass}`}>
          <h3 className="sp-logs-title">Live Logs</h3>
          <div className="sp-logs-container">
            {scanLogs.length === 0 && (
              <div className="sp-log-line sp-log-info">
                <span className="sp-log-ts">{new Date().toLocaleTimeString('en-US', { hour12: false })}</span>
                <span>Initializing pipeline...</span>
              </div>
            )}
            {scanLogs.map((log, i) => (
              <div key={i} className={`sp-log-line sp-log-${log.level}`}>
                <span className="sp-log-ts">{log.timestamp}</span>
                <span>{log.message}</span>
              </div>
            ))}
            <div ref={logsEndRef} />
          </div>
        </div>

        {/* Action Buttons */}
        <div className="sp-actions">
          <button
            className="sp-btn-primary"
            onClick={() => setCurrentPage('scanResults')}
            disabled={!scanComplete}
          >
            View Results {!scanComplete && '(When Complete)'}
          </button>
          <button className="sp-btn-secondary" onClick={() => setCurrentPage('dashboard')}>
            Back to Dashboard
          </button>
        </div>
      </div>
    );
  };

  const NewScanPage = () => {
    const [url, setUrl] = useState('');
    const [branch, setBranch] = useState('main');
    const [includeDeps, setIncludeDeps] = useState(false);
    const [scanQueue] = useState([]);

    return (
      <div className={`new-scan-page ${darkMode ? 'dark' : 'light'}`}>
        <div className="new-scan-header">
          <h1 className="page-title">New Scan</h1>
          <p className="page-subtitle">Configure and start a new security scan</p>
        </div>

        {/* Config Card */}
        <div className="scan-config-card">
          <div className="form-group">
            <label className="form-label">GitHub Repository URL</label>
            <input
              type="text"
              placeholder="https://github.com/organization/repository"
              className="scan-input"
              value={url}
              onChange={e => setUrl(e.target.value)}
            />
            <p className="form-hint">Enter the full URL of your GitHub repository</p>
          </div>

          <div className="form-group">
            <label className="form-label">
              <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{display:'inline',marginRight:'6px',verticalAlign:'middle'}}><path d="M6 3v12"/><circle cx="18" cy="6" r="3"/><circle cx="6" cy="18" r="3"/><path d="M18 9a9 9 0 0 1-9 9"/></svg>
              Branch Selection
            </label>
            <div className="scan-select-wrapper">
              <select className="scan-select" value={branch} onChange={e => setBranch(e.target.value)}>
                <option value="main">main</option>
                <option value="master">master</option>
                <option value="develop">develop</option>
                <option value="staging">staging</option>
              </select>
              <svg className="select-chevron" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><polyline points="6 9 12 15 18 9"/></svg>
            </div>
          </div>

          <div className="form-group scan-checkbox-group">
            <label className="scan-checkbox-label">
              <input
                type="checkbox"
                className="scan-checkbox"
                checked={includeDeps}
                onChange={e => setIncludeDeps(e.target.checked)}
              />
              <div className="scan-checkbox-content">
                <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{display:'inline',marginRight:'6px',color:'#3b82f6'}}><path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z"/></svg>
                <strong>Include dependencies scan</strong>
                <p className="checkbox-hint">Scan package dependencies for known vulnerabilities (npm, pip, etc.)</p>
              </div>
            </label>
          </div>

          <button onClick={() => startScan(url)} className="start-scan-btn">
            Start Scan
          </button>
        </div>
      </div>
    );
  };

  const ScanResultsPage = () => {
    const [sevFilter, setSevFilter] = useState('All Severities');
    const [fileFilter, setFileFilter] = useState('All File Types');
    const [catFilter, setCatFilter] = useState('All Categories');

    const counts = {
      total: vulnerabilities.length,
      critical: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'critical').length,
      high: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'high').length,
      medium: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'medium').length,
      low: vulnerabilities.filter(v => v.severity?.toLowerCase() === 'low').length,
    };

    const riskScore = Math.min(10, (counts.total * 0.4) + (counts.critical * 1.5)).toFixed(1);
    const themeClass = darkMode ? 'dark' : 'light';

    const filteredVulns = vulnerabilities.filter(v => {
      const matchSev = sevFilter === 'All Severities' || v.severity?.toLowerCase() === sevFilter.toLowerCase();
      const matchCat = catFilter === 'All Categories' || v.category?.toLowerCase() === catFilter.toLowerCase();
      return matchSev && matchCat;
    });

    return (
      <div className={`scan-results-page ${themeClass}`}>
        <div className="scan-results-header">
          <div className="header-text">
            <h1 className="res-title">Scan Results</h1>
            <div className="res-meta">
              <span className="res-repo">{scanningRepo.replace('https://github.com/', '')}</span>
              <span className="res-dot">•</span>
              <span className="res-date">Scanned: {new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', hour: '2-digit', minute: '2-digit' })}</span>
              <span className="res-dot">•</span>
              <span className="res-risk-label">Risk Score: <span className="risk-val-red">{riskScore}</span></span>
            </div>
          </div>
          <button className="btn-export-premium" onClick={() => window.print()}><Download size={16} /> Export Report</button>
        </div>

        {/* Stats Grid - MATCHING MOCKUP 4-COLUMN */}
        <div className="stats-grid-results">
          <div className={`stat-card-results total ${themeClass}`}>
            <div className="stat-value-large">{counts.total}</div>
            <div className="stat-label-results">Total Issues</div>
          </div>
          <div className={`stat-card-results red ${themeClass}`}>
            <div className="stat-value-large">{counts.critical}</div>
            <div className="stat-label-results">Critical</div>
          </div>
          <div className={`stat-card-results orange ${themeClass}`}>
            <div className="stat-value-large">{counts.high}</div>
            <div className="stat-label-results">High</div>
          </div>
          <div className={`stat-card-results yellow ${themeClass}`}>
            <div className="stat-value-large">{counts.medium}</div>
            <div className="stat-label-results">Medium</div>
          </div>
        </div>

        {/* Filter Bar */}
        <div className="filters-section-premium">
          <div className="filter-icon-group"><Filter size={18} /></div>
          <div className="filter-dropdowns">
            <select className="filter-select-premium" value={sevFilter} onChange={e => setSevFilter(e.target.value)}>
              <option>All Severities</option>
              <option>Critical</option>
              <option>High</option>
              <option>Medium</option>
              <option>Low</option>
            </select>
            <select className="filter-select-premium" value={fileFilter} onChange={e => setFileFilter(e.target.value)}>
              <option>All File Types</option>
              <option>Javascript</option>
              <option>Python</option>
            </select>
            <select className="filter-select-premium" value={catFilter} onChange={e => setCatFilter(e.target.value)}>
              <option>All Categories</option>
              <option>Injection</option>
              <option>XSS</option>
              <option>Secrets</option>
            </select>
          </div>
        </div>

        {/* Vulnerability List */}
        <div className="vulnerabilities-list-premium">
          {filteredVulns.length === 0 ? (
            <div className="vuln-empty">No vulnerabilities found matching filters.</div>
          ) : (
            filteredVulns.map((v, i) => (
              <div key={i} className={`vulnerability-card-premium ${themeClass}`}>
                <div className="vulnerability-header">
                  <div className="vulnerability-title-row">
                    <div className={`vuln-icon-box-premium ${v.severity?.toLowerCase()}`}>
                      <AlertTriangle size={20} />
                    </div>
                    <div className="vuln-title-group">
                      <div className="vuln-title-badges">
                        <h3 className="vulnerability-title-premium">{v.title}</h3>
                        <span className={`pill-badge severity-${v.severity?.toLowerCase()}`}>{v.severity}</span>
                        <span className="pill-badge category">{v.category}</span>
                      </div>
                      <div className="vulnerability-file-premium">
                        <FileText size={14} className="icon-muted" /> 
                        <span>{v.file} <span className="path-sep">•</span> Line <span className="line-num">{v.line}</span></span>
                      </div>
                    </div>
                  </div>
                </div>
                <div className="vulnerability-body-premium">
                  <p className="vulnerability-description-premium">{v.description || "Detailed vulnerability description would be here."}</p>
                </div>
                <div className="vulnerability-actions-premium">
                  <button className="btn-view-fix-premium" onClick={() => {
                    console.log("View Fix clicked for:", v.title);
                    handleViewDetails(v);
                    setCurrentPage('remediation');
                  }}>View Fix</button>
                  <button className="btn-mark-resolved-premium" onClick={async () => {
                    if (window.confirm(`Mark "${v.title}" as resolved?`)) {
                      try {
                        const vid = v.id || v._id;
                        await authenticatedFetch(`/api/vulnerability/${vid}/resolve`, { method: 'POST' });
                        // Update local state to remove it from the current view
                        setVulnerabilities(prev => prev.filter(item => (item.id || item._id) !== vid));
                        // Refresh dashboard scans background data if needed
                      } catch (err) {
                        console.error("Failed to resolve:", err);
                      }
                    }
                  }}><CheckCircle size={14} /> Mark Resolved</button>
                </div>
              </div>
            ))
          )}
        </div>
      </div>
    );
  };

  const RemediationPage = () => {
    const vuln = selectedVulnerability;
    const themeClass = darkMode ? 'dark' : 'light';
    const [fixedCode, setFixedCode] = useState('');
    const [fixExplanation, setFixExplanation] = useState('');
    const [loadingFix, setLoadingFix] = useState(false);
    const [fixError, setFixError] = useState('');
    const [activeTab, setActiveTab] = useState('issue'); // 'issue' or 'research'
    const [agentLogs, setAgentLogs] = useState([]);
    const [isResearching, setIsResearching] = useState(false);

    useEffect(() => {
      // Use both id and _id to support both SQLite and MongoDB backends
      const vulnId = vuln?.id || vuln?._id;
      if (!vulnId) return;
      
      console.log("RemediationPage - Triggering Fix Generation for:", vuln.title);
      setLoadingFix(true);
      setFixError(null);
      setFixedCode(''); // Clear previous fix
      
      authenticatedFetch('/api/fix', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          vulnerability: vuln,
          repo_url: scanningRepo
        })
      })
      .then(res => res.json())
      .then(data => {
        if (data.fixed_code) {
          console.log("RemediationPage - Fix Generated Successfully");
          setFixedCode(data.fixed_code);
          setFixExplanation(data.explanation || '');
          setLoadingFix(false);
        } else {
          setFixError(data.error || 'Failed to generate fix');
          setLoadingFix(false);
        }
      })
      .catch(err => {
        console.error('Fix error:', err);
        setFixError('Failed to generate AI fix.');
        setLoadingFix(false);
      });
    }, [vuln]);

    // Agentic Research Trigger
    useEffect(() => {
      if (activeTab === 'research' && agentLogs.length === 0 && vuln) {
        setIsResearching(true);
        setAgentLogs(["[AGENT] Initializing autonomous researcher..."]);
        
        authenticatedFetch('/api/agent/research', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ vulnerability: vuln })
        })
        .then(res => res.json())
        .then(data => {
          if (data.success) {
            setAgentLogs(data.logs || []);
            // Update vuln with agent insight if available
            if (data.insight) {
              setSelectedVulnerability(prev => ({ ...prev, insight: data.insight }));
            }
          } else {
            setAgentLogs(prev => [...prev, `[AGENT ERR] ${data.error || 'Research failed'}`]);
          }
          setIsResearching(false);
        })
        .catch(err => {
          setAgentLogs(prev => [...prev, `[AGENT ERR] Network error during research: ${err.message}`]);
          setIsResearching(false);
        });
      }
    }, [activeTab, vuln]);

    if (!vuln) {
      return (
        <div className={`remediation-page ${themeClass}`}>
          <div className="rem-header">
            <h1>AI Remediation</h1>
            <button className="rem-back-btn" onClick={() => setCurrentPage('scanResults')}>← Back</button>
          </div>
          <div className="rem-empty">No vulnerability selected. Please pick one from the scan results.</div>
        </div>
      );
    }

    const vulnerableCode = vuln.vulnerableCode || vuln.vulnerable_code || '';

    return (
      <div className={`remediation-page ${themeClass}`}>
        <div className="rem-header">
          <div className="rem-header-info">
            <h1>AI Remediation</h1>
            <p>AI-powered fix for security vulnerability</p>
          </div>
          <button className="rem-back-btn" onClick={() => setCurrentPage('scanResults')}>← Back to Results</button>
        </div>

        <div className="rem-container">
          {/* Sidebar Area */}
          <div className="rem-sidebar">
            <div className="rem-tabs">
              <button 
                className={`rem-tab ${activeTab === 'issue' ? 'active' : ''}`}
                onClick={() => setActiveTab('issue')}
              >Selected Issue</button>
              <button 
                className={`rem-tab ${activeTab === 'research' ? 'active' : ''}`}
                onClick={() => setActiveTab('research')}
              >Agentic Research <span className="v6-tag">V6.0</span></button>
            </div>

            {activeTab === 'issue' ? (
              <div className={`rem-card ${themeClass}`}>
                <h3 className="rem-card-title">Selected Issue</h3>
                <div className="rem-detail-list">
                  <div className="rem-detail-item">
                    <span className="rem-detail-label">Title</span>
                    <div className="rem-detail-value">{vuln.title}</div>
                  </div>
                  <div className="rem-detail-item">
                    <span className="rem-detail-label">Severity</span>
                    <div className="rem-detail-value">
                      <span className={`rem-badge-pill ${vuln.severity?.toLowerCase()}`}>{vuln.severity}</span>
                    </div>
                  </div>
                  <div className="rem-detail-item">
                    <span className="rem-detail-label">File</span>
                    <div className="rem-detail-value rem-path-text">{vuln.file}</div>
                  </div>
                  <div className="rem-detail-item">
                    <span className="rem-detail-label">Line</span>
                    <div className="rem-detail-value">{vuln.line}</div>
                  </div>
                </div>
              </div>
            ) : (
              <div className={`rem-card agentic ${themeClass}`}>
                <h3 className="rem-card-title"><Shield size={16} className="text-blue" /> Research Logs</h3>
                <div className="agent-terminal">
                   {agentLogs.map((log, i) => (
                     <div key={i} className="agent-log">{log}</div>
                   ))}
                   {isResearching && (
                     <div className="agent-log pulse">[AGENT] Reasoning phase in progress...</div>
                   )}
                   {!isResearching && agentLogs.length === 0 && (
                     <div className="agent-log-empty">Initializing autonomous session...</div>
                   )}
                </div>
              </div>
            )}

            <div className={`rem-card glass ${themeClass}`}>
              <h3 className="rem-card-title"><Sparkles size={16} className="text-blue" /> Why this fix works</h3>
              <p className="rem-card-desc">
                {fixExplanation || vuln.insight || "This fix addresses the core vulnerability by implementing secure coding patterns and input validation to prevent exploitation."}
              </p>
            </div>
          </div>

          {/* Main Workspace Area */}
          <div className="rem-main">
            <div className="rem-code-card">
              <div className="rem-code-bar red">
                <span className="rem-status-dot red"></span>
                Vulnerable Code
              </div>
              <div className="rem-editor-area">
                {vulnerableCode ? vulnerableCode.split('\n').map((line, i) => {
                  const currentLineNum = (vuln.start_line || 1) + i;
                  const isVulnerableLine = currentLineNum === vuln.line;
                  return (
                    <div key={i} className={`rem-editor-row ${isVulnerableLine ? 'error' : ''}`}>
                      <div className="rem-editor-num">{currentLineNum}</div>
                      <div className="rem-editor-code">{line}</div>
                    </div>
                  );
                }) : <div className="rem-editor-empty">No vulnerable code context available.</div>}
              </div>
            </div>

            <div className="rem-code-card">
              <div className="rem-code-bar green">
                <Sparkles size={16} className="text-green" />
                AI Suggested Fix
              </div>
              <div className="rem-editor-area">
                {loadingFix ? (
                  <div className="rem-editor-loading">Generating secure remediation fix...</div>
                ) : fixError ? (
                  <div className="rem-editor-error">{fixError}</div>
                ) : (
                  (() => {
                    const vLines = vulnerableCode.split('\n');
                    const fLines = fixedCode.split('\n');
                    return fLines.map((line, i) => {
                      const currentLineNum = (vuln.start_line || 1) + i;
                      // Highlight if this specific line was changed compared to the original
                      const isChanged = line !== vLines[i];
                      return (
                        <div key={i} className={`rem-editor-row ${isChanged ? 'success' : ''}`}>
                          <div className="rem-editor-num">{currentLineNum}</div>
                          <div className="rem-editor-code">{line}</div>
                        </div>
                      );
                    });
                  })()
                )}
              </div>
            </div>

            {/* Threat Analysis - Moved inside main scrollable area for perfect alignment */}
            <div className="rem-footer-analysis">
              <h3 className="rem-footer-title">Threat Analysis</h3>
              <div className="rem-threat-sections">
                <div className="rem-threat-block">
                  <h4 className="rem-threat-subtitle">Vulnerability Identification</h4>
                  <div className="rem-footer-text">
                    <p className="rem-brief-intro">
                      The application implements <strong>{vuln.category}</strong> logic which enables the identified <strong>{vuln.title}</strong> flaw.
                    </p>
                    <p>
                      {vuln.description || "Detailed vulnerability analysis for the current context."}
                    </p>
                  </div>
                </div>
                <div className="rem-threat-block">
                  <h4 className="rem-threat-subtitle">Potential Impact</h4>
                  <p className="rem-footer-text">
                    {vuln.impact || "Exploitation of this vulnerability could lead to unauthorized system access or sensitive data exposure."}
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  };
  const ReportsPage = () => {
    const [scans, setScans] = useState([]);
    const [analytics, setAnalytics] = useState(null);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
      if (token) {
        Promise.all([
          authenticatedFetch('/api/scans').then(r => r.json()),
          authenticatedFetch('/api/analytics').then(r => r.json())
        ]).then(([scansData, analyticsData]) => {
          setScans(Array.isArray(scansData) ? scansData : []);
          setAnalytics(analyticsData);
          setLoading(false);
        }).catch(() => setLoading(false));
      } else {
        setLoading(false);
      }
    }, [token]);

    const stats = (analytics && analytics.severity && Object.values(analytics.severity).some(v => v > 0)) ? analytics : {
      severity: { critical: 1, high: 1, medium: 1, low: 1 },
      categories: []
    };

    // Build proper SVG pie chart path segments
    const COLORS = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' };
    const CX = 100, CY = 100, R = 80;

    const buildPieSlices = () => {
      // PROPER SEVERITY ORDERING (Critical -> High -> Medium -> Low)
      const ORDER = ['critical', 'high', 'medium', 'low'];
      const entries = ORDER
        .filter(k => stats.severity[k] !== undefined)
        .map(k => [k, stats.severity[k]]);

      const total = entries.reduce((s, [, v]) => s + v, 0);
      if (total === 0) return [];

      let startAngle = -Math.PI / 2; // start from top
      return entries
        .map(([key, value]) => {
          const pct = value / total;
          if (pct === 0) return null; // Skip slices with 0 count
          
          const angle = (pct === 1 ? 0.9999 : pct) * 2 * Math.PI;
          const endAngle = startAngle + angle;
          const midAngle = startAngle + angle / 2;

          const x1 = CX + R * Math.cos(startAngle);
          const y1 = CY + R * Math.sin(startAngle);
          const x2 = CX + R * Math.cos(endAngle);
          const y2 = CY + R * Math.sin(endAngle);

          const labelR = R + 30; // Closer to avoid clipping
          const lx = CX + labelR * Math.cos(midAngle);
          const ly = CY + labelR * Math.sin(midAngle);

          const large = angle > Math.PI ? 1 : 0;
          const d = `M ${CX} ${CY} L ${x1} ${y1} A ${R} ${R} 0 ${large} 1 ${x2} ${y2} Z`;

          const sliceColor = COLORS[key];
          const sliceLabel = `${key.charAt(0).toUpperCase() + key.slice(1)} ${Math.round(pct * 100)}%`;

          startAngle = endAngle;
          return { key, pct, d, lx, ly, color: sliceColor, label: sliceLabel };
        })
        .filter(Boolean);
    };

    const slices = buildPieSlices();
    const themeClass = darkMode ? 'dark' : 'light';

    return (
      <div className={`reports-analytics-page ${themeClass}`}>
        <div className="reports-header-row">
          <div className="reports-title-group">
            <h1 className="reports-page-title">Reports</h1>
            <p className="reports-page-subtitle">Download and manage security reports</p>
          </div>
          <button onClick={() => setCurrentPage('newScan')} className="btn-generate-report">Generate New Report</button>
        </div>

        <div className="reports-analytics-grid">
          {/* Severity Distribution Chart */}
          <div className={`analytics-card ${themeClass}`}>
            <h3 className="analytics-card-title">Severity Distribution</h3>
            <div className="pie-full-wrapper">
              <svg viewBox="-110 -30 420 260" className="pie-svg">
                {slices.map((s, i) => (
                  <g key={i}>
                    <path d={s.d} fill={s.color} stroke="transparent" strokeWidth="1" />
                    <line
                      x1={CX + (R + 4) * Math.cos(Math.atan2(s.ly - CY, s.lx - CX))}
                      y1={CY + (R + 4) * Math.sin(Math.atan2(s.ly - CY, s.lx - CX))}
                      x2={s.lx}
                      y2={s.ly}
                      stroke={s.color}
                      strokeWidth="0.8"
                      strokeDasharray="2 1"
                    />
                    <text
                      x={s.lx}
                      y={s.ly}
                      textAnchor={s.lx > CX ? 'start' : 'end'}
                      dominantBaseline="middle"
                      fill={s.color}
                      fontSize="8.5"
                      fontWeight="700"
                    >
                      {s.label}
                    </text>
                  </g>
                ))}
              </svg>
              <div className="pie-legend-row">
                {Object.entries(stats.severity).map(([key, val]) => (
                  <div key={key} className="legend-item">
                    <span className={`dot ${key}`}></span>
                    <span className="legend-text">
                      {key.charAt(0).toUpperCase() + key.slice(1)}: {analytics ? val : '–'}
                    </span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Issue Categories Chart */}
          <div className={`analytics-card ${themeClass}`}>
            <h3 className="analytics-card-title">Top Vulnerability Categories</h3>
            <div className="chart-container bar-chart-container">
              {stats.categories.length > 0 ? (
                <div className="bar-chart-wrapper">
                  <div className="y-axis">
                    <span>{Math.max(...stats.categories.map(c => c.count), 5)}</span>
                    <span>{Math.round(Math.max(...stats.categories.map(c => c.count), 5)/2)}</span>
                    <span>0</span>
                  </div>
                  <div className="bars-area">
                    {stats.categories.map((cat, i) => (
                      <div key={i} className="bar-group">
                        <div className="bar" style={{ 
                          height: `${(cat.count / Math.max(...stats.categories.map(c => c.count), 1)) * 100}%`,
                          transition: 'height 1s ease'
                        }}></div>
                        <span className="bar-label">{cat.name}</span>
                      </div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="chart-placeholder">Run a scan to see category breakdown</div>
              )}
            </div>
          </div>
        </div>

        <div className="available-reports-section">
          <h2 className="section-header-title">Historical Reports</h2>
          <div className="reports-list">
            {loading ? (
              <div className="reports-loading">Fetching your reports...</div>
            ) : scans.length === 0 ? (
              <div className="reports-empty-state">No security reports found. Start your first scan to generate one!</div>
            ) : (
              scans.map((s, i) => (
                <div key={s.id || i} className={`report-item-card ${themeClass}`}>
                  <div className="report-item-icon">
                    <Shield size={24} className="icon-blue" />
                  </div>
                  <div className="report-item-info">
                    <h4 className="report-item-title">{s.repo_url?.split('/').pop() || 'Security Audit'}</h4>
                    <div className="report-item-meta">
                      <span className="meta-repo">{s.repo_url?.replace('https://github.com/', '')}</span>
                      <span className="meta-sep">•</span>
                      <span className="meta-date">{new Date(s.date).toLocaleDateString()}</span>
                      <span className="meta-sep">•</span>
                      <span className="meta-issues">{s.vulnerability_count || 0} vulnerabilities detected</span>
                    </div>
                  </div>
                  <div className="report-item-actions">
                    <button className="btn-action-download pdf" onClick={async () => { 
                      try {
                        const res = await authenticatedFetch(`/api/scan/${s.id}`);
                        const data = await res.json();
                        setVulnerabilities(data.vulnerabilities || []);
                        setScanningRepo(s.repo_url); 
                        setCurrentPage('scanResults'); 
                        setTimeout(() => window.print(), 800);
                      } catch (e) {
                        console.error("Failed to load report for PDF:", e);
                      }
                    }}>
                      <Download size={14} /> PDF
                    </button>
                    <button className="btn-action-download view" onClick={async () => { 
                      try {
                        const res = await authenticatedFetch(`/api/scan/${s.id}`);
                        const data = await res.json();
                        setVulnerabilities(data.vulnerabilities || []);
                        setScanningRepo(s.repo_url); 
                        setCurrentPage('scanResults'); 
                      } catch (e) {
                        console.error("Failed to load report:", e);
                      }
                    }}>
                      View
                    </button>
                    <button className="btn-action-download json" onClick={() => {
                        const blob = new Blob([JSON.stringify(s, null, 2)], { type: 'application/json' });
                        const url = URL.createObjectURL(blob);
                        const a = document.createElement('a'); a.href = url; a.download = `report-${s.id}.json`; a.click();
                    }}>
                      <Download size={14} /> JSON
                    </button>
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      </div>
    );
  };

  return (
    <div className={`app ${darkMode ? 'dark-mode' : 'light-mode'}`}>
      {!token ? (
        <LoginPage />
      ) : (
        <div className={`app-container ${darkMode ? 'dark' : 'light'}`}>
          <Sidebar />
          <div className={`main-content ${darkMode ? 'dark' : 'light'}`}>
            <TopBar />
            <div className={`page-content ${darkMode ? 'dark' : 'light'}`}>
              {currentPage === 'landing' && <Dashboard />}
              {currentPage === 'dashboard' && <Dashboard />}
              {currentPage === 'newScan' && <NewScanPage />}
              {currentPage === 'scanProgress' && <ScanProgressPage />}
              {currentPage === 'scanResults' && <ScanResultsPage />}
              {currentPage === 'remediation' && <RemediationPage />}
              {currentPage === 'reports' && <ReportsPage />}
              {currentPage === 'history' && <ScanHistoryPage />}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default CodeGuardApp;
