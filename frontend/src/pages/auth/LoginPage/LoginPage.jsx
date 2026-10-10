import React from 'react';
import { Shield, ArrowLeft } from 'lucide-react';
import './LoginPage.css';

const LoginPage = ({ darkMode, setCurrentPage, setIsAuthenticated }) => {
    const handleSubmit = (e) => {
        e.preventDefault();
        setIsAuthenticated(true);
        setCurrentPage('dashboard');
    };

    return (
        <div className={`auth-page ${darkMode ? 'dark' : 'light'}`}>
            <div className="auth-container">
                <button onClick={() => setCurrentPage('landing')} className="back-to-landing">
                    <span>← Back to Home</span>
                </button>
                <div className="auth-header">
                    <div className="logo-center">
                        <Shield className="logo-icon-large" />
                        <span className="logo-text-large">CodeGuard</span>
                    </div>
                    <h2 className="auth-title">Welcome back</h2>
                    <p className="auth-subtitle">Sign in to your account</p>
                </div>
                <div className="auth-card">
                    <form onSubmit={handleSubmit} className="auth-form">
                        <div className="form-group">
                            <label className="form-label">Email</label>
                            <input type="email" placeholder="you@example.com" className="form-input" required />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Password</label>
                            <input type="password" placeholder="••••••••" className="form-input" required />
                        </div>
                        <div className="form-checkbox">
                            <input type="checkbox" id="remember" />
                            <label htmlFor="remember" className="checkbox-label">Remember me</label>
                        </div>
                        <button type="submit" className="btn btn-primary btn-full">Sign in</button>
                        <button type="button" onClick={() => setCurrentPage('forgot')} className="link-btn">
                            Forgot password?
                        </button>
                    </form>
                    <div className="divider">or continue with</div>
                    <button className="btn btn-github btn-full">
                        <span>Continue with GitHub</span>
                    </button>
                </div>
                <div className="auth-switch">
                    Don't have an account? <button onClick={() => setCurrentPage('signup')} className="link">Sign up</button>
                </div>
            </div>
        </div>
    );
};

export default LoginPage;
