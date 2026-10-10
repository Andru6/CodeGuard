import React from 'react';
import { Shield } from 'lucide-react';
import './SignUpPage.css';

const SignUpPage = ({ darkMode, setCurrentPage, setIsAuthenticated }) => {
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
                    <h2 className="auth-title">Create account</h2>
                    <p className="auth-subtitle">Start securing your code today</p>
                </div>
                <div className="auth-card">
                    <form onSubmit={handleSubmit} className="auth-form">
                        <div className="form-group">
                            <label className="form-label">Full Name</label>
                            <input type="text" placeholder="John Doe" className="form-input" required />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Email</label>
                            <input type="email" placeholder="you@example.com" className="form-input" required />
                        </div>
                        <div className="form-group">
                            <label className="form-label">Password</label>
                            <input type="password" placeholder="••••••••" className="form-input" required />
                        </div>
                        <div className="form-checkbox">
                            <input type="checkbox" id="terms" required />
                            <label htmlFor="terms" className="checkbox-label">
                                I agree to the Terms and Conditions
                            </label>
                        </div>
                        <button type="submit" className="btn btn-primary btn-full">Create account</button>
                    </form>
                    <div className="divider">or continue with</div>
                    <button className="btn btn-github btn-full">
                        <span>Continue with GitHub</span>
                    </button>
                </div>
                <div className="auth-switch">
                    Already have an account? <button onClick={() => setCurrentPage('login')} className="link">Sign in</button>
                </div>
            </div>
        </div>
    );
};

export default SignUpPage;
