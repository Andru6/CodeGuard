import React from 'react';
import { Search, Sun, Moon, Shield, RefreshCw, FileText } from 'lucide-react';
import './LandingPage.css';

const LandingPage = ({ darkMode, setDarkMode, setCurrentPage }) => {
    const scrollToFeatures = () => {
        const featuresSection = document.getElementById('features');
        if (featuresSection) featuresSection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    };

    const FeatureCard = ({ icon, title, description }) => (
        <div className="feature-card">
            <div className="feature-icon">{icon}</div>
            <h3 className="feature-title">{title}</h3>
            <p className="feature-description">{description}</p>
        </div>
    );

    return (
        <div className={`landing-page ${darkMode ? 'dark' : 'light'}`}>
            <nav className="landing-nav">
                <div className="logo">
                    <Shield className="logo-icon" />
                    <span className="logo-text">CodeGuard</span>
                </div>
                <div className="nav-links">
                    <button onClick={scrollToFeatures} className="nav-link">Features</button>
                    <button onClick={() => setCurrentPage('login')} className="nav-link">Login</button>
                    <button onClick={() => setCurrentPage('signup')} className="btn btn-primary">Sign Up</button>
                    <button onClick={() => setDarkMode(!darkMode)} className="theme-toggle">
                        {darkMode ? <Sun size={20} /> : <Moon size={20} />}
                    </button>
                </div>
            </nav>
            <div className="hero-section">
                <h1 className="hero-title">Scan your GitHub repo for<br />vulnerabilities using AI</h1>
                <p className="hero-subtitle">Automated security scanning with AI-powered remediation for your code repositories</p>
                <div className="hero-actions">
                    <button onClick={() => setCurrentPage('signup')} className="btn btn-primary btn-large">Start Scanning</button>
                </div>
                <div id="features" className="features-grid">
                    <FeatureCard icon={<Search size={40} />} title="SAST Scan" description="Static analysis security testing for comprehensive code review" />
                    <FeatureCard icon={<RefreshCw size={40} />} title="AI Fix Suggestions" description="Intelligent remediation powered by advanced AI models" />
                    <FeatureCard icon={<FileText size={40} />} title="Reports" description="Detailed vulnerability reports with export options" />
                    <FeatureCard icon={<Shield size={40} />} title="Background Jobs" description="Async scanning with Celery and Redis for scalability" />
                </div>
            </div>
            <footer className="landing-footer">
                <div className="footer-content">
                    <div className="footer-section">
                        <div className="logo">
                            <Shield className="logo-icon" />
                            <span className="logo-text">CodeGuard</span>
                        </div>
                        <p className="footer-description">AI-powered security scanning for modern development teams</p>
                    </div>
                    <div className="footer-section">
                        <h4 className="footer-title">Company</h4>
                        <ul className="footer-links">
                            <li><a href="#about" className="footer-link">About</a></li>
                            <li><a href="#contact" className="footer-link">Contact</a></li>
                        </ul>
                    </div>
                    <div className="footer-section">
                        <h4 className="footer-title">Links</h4>
                        <ul className="footer-links">
                            <li><a href="#github" className="footer-link">GitHub</a></li>
                            <li><a href="#privacy" className="footer-link">Privacy</a></li>
                        </ul>
                    </div>
                </div>
            </footer>
        </div>
    );
};

export default LandingPage;
