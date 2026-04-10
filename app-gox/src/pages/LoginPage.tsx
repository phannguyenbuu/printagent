import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import { GoogleLogin } from '@react-oauth/google';
import { useAuthStore } from '../stores/authStore';
import { AnimatedButton } from '../components/ui/AnimatedButton';
import { LoadingSpinner } from '../components/ui/LoadingSpinner';

type Tab = 'login' | 'register' | 'forgot';
type ForgotStep = 'email' | 'otp' | 'newpw';

const QUICK_ACCOUNTS = [
  { email: 'supplier1@goxprint.vn', password: 'password123', label: '🏭 Nhà cung cấp - Nguyễn Văn An' },
  { email: 'supplier3@phuongnam.vn', password: 'password123', label: '📦 Nhà cung cấp đa công ty - Hoàng Thị Mai' },
  { email: 'tech1@kythuat.vn', password: 'password123', label: '🔧 Kỹ thuật viên - Lê Minh Cường' },
];

const EyeIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>
  </svg>
);
const EyeOffIcon = () => (
  <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
    <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/>
  </svg>
);

export function LoginPage() {
  const navigate = useNavigate();
  const login = useAuthStore((s) => s.login);
  const register = useAuthStore((s) => s.register);
  const loginWithGoogle = useAuthStore((s) => s.loginWithGoogle);

  const [tab, setTab] = useState<Tab>('login');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [phoneNumber, setPhoneNumber] = useState('');
  const [address, setAddress] = useState('');
  
  const [showPassword, setShowPassword] = useState(false);
  const [showConfirmPassword, setShowConfirmPassword] = useState(false);

  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const [forgotStep, setForgotStep] = useState<ForgotStep>('email');
  const [forgotEmail, setForgotEmail] = useState('');
  const [otpInput, setOtpInput] = useState('');
  const [otpCode, setOtpCode] = useState(''); 
  const [newPw, setNewPw] = useState('');
  const [confirmNewPw, setConfirmNewPw] = useState('');
  const [pwResetDone, setPwResetDone] = useState(false);

  const handleSuccess = () => navigate('/workspace');

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setLoading(true);
    try {
      const result = await login(email, password);
      if (result.success) handleSuccess();
      else setError(result.error);
    } catch { setError('Đã xảy ra lỗi. Vui lòng thử lại.'); }
    finally { setLoading(false); }
  };

  const handleRegister = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!fullName.trim()) { setError('Vui lòng nhập họ tên'); return; }
    if (!phoneNumber.trim()) { setError('Vui lòng nhập số điện thoại'); return; }
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*[!@#$%^&*(),.?":{}|<>]).{8,}$/;
    if (!passwordRegex.test(password)) {
      setError('Mật khẩu phải từ 8 ký tự, bao gồm chữ hoa, chữ thường và ít nhất một ký tự đặc biệt');
      return;
    }
    if (password !== confirmPassword) { setError('Mật khẩu xác nhận không khớp'); return; }
    setLoading(true);
    try {
      const result = await register(email, password, fullName, phoneNumber, address);
      if (result.success) handleSuccess();
      else setError(result.error || 'Đăng ký thất bại');
    } catch (err: any) {
      setError(err.message || 'Đã xảy ra lỗi. Vui lòng thử lại.');
    } finally { setLoading(false); }
  };

  const handleGoogleSuccess = async (credentialResponse: any) => {
    setError('');
    setLoading(true);
    try {
      const result = await loginWithGoogle(credentialResponse.credential);
      if (result.success) handleSuccess();
      else setError(result.error);
    } catch (err: any) {
      setError(err.message || 'Đăng nhập Google thất bại');
    } finally { setLoading(false); }
  };

  const handleForgotPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (!forgotEmail) { setError('Vui lòng nhập email'); return; }
    setLoading(true);
    await new Promise((r) => setTimeout(r, 800));
    const code = String(Math.floor(100000 + Math.random() * 900000));
    setOtpCode(code);
    setLoading(false);
    setForgotStep('otp');
    console.info(`[DEV] OTP code for ${forgotEmail}: ${code}`);
  };

  const handleVerifyOtp = (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (otpInput.trim() !== otpCode) {
      setError('Mã xác nhận không đúng. Vui lòng kiểm tra lại.');
      return;
    }
    setForgotStep('newpw');
  };

  const handleResetPassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    if (newPw.length < 6) { setError('Mật khẩu phải có ít nhất 6 ký tự'); return; }
    if (newPw !== confirmNewPw) { setError('Mật khẩu xác nhận không khớp'); return; }
    setLoading(true);
    await new Promise((r) => setTimeout(r, 600));
    setLoading(false);
    setPwResetDone(true);
  };

  const handleQuickLogin = (acc: typeof QUICK_ACCOUNTS[0]) => {
    setEmail(acc.email);
    setPassword(acc.password);
    setError('');
    setLoading(true);
    login(acc.email, acc.password)
      .then((r) => { if (r.success) handleSuccess(); else setError(r.error); })
      .catch(() => setError('Đã xảy ra lỗi.'))
      .finally(() => setLoading(false));
  };

  const switchTab = (t: Tab) => {
    setTab(t); setError('');
    setForgotStep('email'); setForgotEmail(''); setOtpInput(''); setOtpCode('');
    setNewPw(''); setConfirmNewPw(''); setPwResetDone(false);
    setShowPassword(false);
    setShowConfirmPassword(false);
  };

  return (
    <div style={styles.container}>
      <motion.div
        style={styles.formWrapper}
        initial={{ opacity: 0, y: 30 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.5, ease: [0.4, 0, 0.2, 1] }}
      >
        <div style={styles.logoArea}>
          <motion.div
            style={styles.logoGlow}
            animate={{ boxShadow: ['0 0 20px rgba(0,212,255,0.2)', '0 0 40px rgba(0,212,255,0.4)', '0 0 20px rgba(0,212,255,0.2)'] }}
            transition={{ duration: 3, repeat: Infinity, ease: 'easeInOut' }}
          >
            <span style={styles.logoIcon}>⚙</span>
          </motion.div>
          <h1 style={styles.title}>Quản lý Sửa chữa Máy móc</h1>
        </div>

        <div style={styles.tabs}>
          <button
            style={{ ...styles.tab, ...(tab === 'login' ? styles.tabActive : {}) }}
            onClick={() => switchTab('login')}
          >Đăng nhập</button>
          <button
            style={{ ...styles.tab, ...(tab === 'register' ? styles.tabActive : {}) }}
            onClick={() => switchTab('register')}
          >Đăng ký</button>
        </div>
        
        {tab !== 'forgot' && (
          <div style={{ display: 'flex', justifyContent: 'center', marginBottom: '16px' }}>
            {import.meta.env.VITE_GOOGLE_CLIENT_ID && <GoogleLogin onSuccess={handleGoogleSuccess} onError={() => setError("Google Login Failed")} useOneTap theme="filled_blue" shape="pill" text={tab === "login" ? "signin_with" : "signup_with"} width="380" />}
          </div>
        )}

        {tab !== 'forgot' && (
          <div style={styles.divider}>
            <span style={styles.dividerLine} />
            <span style={styles.dividerText}>hoặc</span>
            <span style={styles.dividerLine} />
          </div>
        )}

        {tab === 'login' && (
          <div style={styles.quickSection}>
            <p style={styles.quickLabel}>Đăng nhập nhanh</p>
            <div style={styles.quickButtons}>
              {QUICK_ACCOUNTS.map((acc) => (
                <motion.button
                  key={acc.email}
                  style={styles.quickButton}
                  onClick={() => handleQuickLogin(acc)}
                  whileTap={{ scale: 0.97 }}
                  disabled={loading}
                >{acc.label}</motion.button>
              ))}
            </div>
            <div style={{ ...styles.divider, marginTop: '16px' }}>
              <span style={styles.dividerLine} />
              <span style={styles.dividerText}>hoặc nhập thủ công</span>
              <span style={styles.dividerLine} />
            </div>
          </div>
        )}

        {tab !== 'forgot' && (
        <form onSubmit={tab === 'login' ? handleLogin : handleRegister} style={styles.form}>
          {tab === 'register' && (<>
            <div style={styles.field}>
              <label htmlFor="fullName" style={styles.label}>Họ tên <span style={{color: 'var(--color-error)'}}>*</span></label>
              <input id="fullName" type="text" value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                placeholder="Nhập họ tên" style={styles.input} disabled={loading} />
            </div>
            <div style={styles.field}>
              <label htmlFor="phoneNumber" style={styles.label}>Số điện thoại <span style={{color: 'var(--color-error)'}}>*</span></label>
              <input id="phoneNumber" type="tel" value={phoneNumber}
                onChange={(e) => setPhoneNumber(e.target.value)}
                placeholder="Nhập số điện thoại" style={styles.input} disabled={loading} />
            </div>
            <div style={styles.field}>
              <label htmlFor="address" style={styles.label}>Địa chỉ</label>
              <input id="address" type="text" value={address}
                onChange={(e) => setAddress(e.target.value)}
                placeholder="Nhập địa chỉ" style={styles.input} disabled={loading} />
            </div>
          </>)}
          
          <div style={styles.field}>
            <label htmlFor="email" style={styles.label}>Email <span style={{color: 'var(--color-error)'}}>*</span></label>
            <input id="email" type="email" value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="Nhập email" style={styles.input}
              autoComplete="email" disabled={loading} />
          </div>
          
          <div style={styles.field}>
            <label htmlFor="password" style={styles.label}>Mật khẩu <span style={{color: 'var(--color-error)'}}>*</span></label>
            <div style={styles.passwordWrapper}>
              <input id="password" type={showPassword ? "text" : "password"} value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Nhập mật khẩu" style={styles.input}
                autoComplete={tab === 'login' ? 'current-password' : 'new-password'}
                disabled={loading} />
              <button type="button" style={styles.eyeBtn} onClick={() => setShowPassword(!showPassword)}>
                {showPassword ? <EyeOffIcon /> : <EyeIcon />}
              </button>
            </div>
          </div>

          {tab === 'register' && (
            <div style={styles.field}>
              <label htmlFor="confirmPassword" style={styles.label}>Xác nhận mật khẩu <span style={{color: 'var(--color-error)'}}>*</span></label>
              <div style={styles.passwordWrapper}>
                <input id="confirmPassword" type={showConfirmPassword ? "text" : "password"} value={confirmPassword}
                  onChange={(e) => setConfirmPassword(e.target.value)}
                  placeholder="Nhập lại mật khẩu" style={styles.input}
                  autoComplete="new-password"
                  disabled={loading} />
                <button type="button" style={styles.eyeBtn} onClick={() => setShowConfirmPassword(!showConfirmPassword)}>
                  {showConfirmPassword ? <EyeOffIcon /> : <EyeIcon />}
                </button>
              </div>
            </div>
          )}

          {tab === 'login' && (
            <div style={{ textAlign: 'right', marginTop: '-8px' }}>
              <button type="button" style={styles.forgotLink} onClick={() => switchTab('forgot')}>
                Quên mật khẩu?
              </button>
            </div>
          )}

          {error && (
            <motion.div style={styles.error}
              initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
              {error}
            </motion.div>
          )}

          <div style={styles.buttonWrapper}>
            {loading ? (
              <div style={styles.spinnerWrapper}><LoadingSpinner size="sm" /></div>
            ) : (
              <AnimatedButton disabled={!email || !password || (tab === 'register' && (!fullName.trim() || !phoneNumber.trim() || !confirmPassword))}>
                {tab === 'login' ? 'Đăng nhập' : 'Đăng ký'}
              </AnimatedButton>
            )}
          </div>
        </form>
        )}

        {tab === 'forgot' && (
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }}>
            <button style={styles.backBtn} onClick={() => switchTab('login')}>← Quay lại đăng nhập</button>
            <div style={styles.stepRow}>
              {(['email', 'otp', 'newpw'] as ForgotStep[]).map((s, i) => (
                <div key={s} style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  <div style={{
                    ...styles.stepDot,
                    background: forgotStep === s ? 'var(--color-primary)'
                      : (['email', 'otp', 'newpw'].indexOf(forgotStep) > i) ? 'var(--color-success)' : 'var(--color-surface-light)',
                  }}>
                    {(['email', 'otp', 'newpw'].indexOf(forgotStep) > i) ? '✓' : i + 1}
                  </div>
                  {i < 2 && <div style={styles.stepLine} />}
                </div>
              ))}
            </div>

            {forgotStep === 'email' && (
              <form onSubmit={handleForgotPassword} style={styles.form}>
                <p style={styles.forgotHint}>Nhập email tài khoản để nhận mã xác nhận.</p>
                <div style={styles.field}>
                  <label htmlFor="forgot-email" style={styles.label}>Email</label>
                  <input id="forgot-email" type="email" value={forgotEmail}
                    onChange={(e) => setForgotEmail(e.target.value)}
                    placeholder="Nhập email đăng ký" style={styles.input}
                    autoComplete="email" disabled={loading} autoFocus />
                </div>
                {error && <motion.div style={styles.error} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>{error}</motion.div>}
                <div style={styles.buttonWrapper}>
                  {loading
                    ? <div style={styles.spinnerWrapper}><LoadingSpinner size="sm" /></div>
                    : <AnimatedButton disabled={!forgotEmail}>Gửi mã xác nhận</AnimatedButton>
                  }
                </div>
              </form>
            )}

            {forgotStep === 'otp' && (
              <form onSubmit={handleVerifyOtp} style={styles.form}>
                <p style={styles.forgotHint}>
                  Mã 6 số đã được gửi tới <strong style={{ color: 'var(--color-text)' }}>{forgotEmail}</strong>.
                </p>
                <div style={styles.field}>
                  <label htmlFor="otp" style={styles.label}>Mã xác nhận</label>
                  <input id="otp" type="text" inputMode="numeric" maxLength={6}
                    value={otpInput} onChange={(e) => setOtpInput(e.target.value.replace(/\D/g, ''))}
                    placeholder="Nhập mã 6 số" style={{ ...styles.input, letterSpacing: '0.3em', fontSize: '1.2rem', textAlign: 'center' }}
                    autoFocus />
                </div>
                {error && <motion.div style={styles.error} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>{error}</motion.div>}
                <div style={styles.buttonWrapper}>
                  <AnimatedButton disabled={otpInput.length !== 6}>Xác nhận mã</AnimatedButton>
                </div>
                <button type="button" style={styles.resendBtn}
                  onClick={() => { setOtpInput(''); setError(''); setForgotStep('email'); }}>
                  Gửi lại mã
                </button>
              </form>
            )}

            {forgotStep === 'newpw' && !pwResetDone && (
              <form onSubmit={handleResetPassword} style={styles.form}>
                <p style={styles.forgotHint}>Tạo mật khẩu mới cho tài khoản của bạn.</p>
                <div style={styles.field}>
                  <label htmlFor="new-pw" style={styles.label}>Mật khẩu mới</label>
                  <input id="new-pw" type="password" value={newPw}
                    onChange={(e) => setNewPw(e.target.value)}
                    placeholder="Tối thiểu 6 ký tự" style={styles.input}
                    autoComplete="new-password" autoFocus />
                </div>
                <div style={styles.field}>
                  <label htmlFor="confirm-pw" style={styles.label}>Xác nhận mật khẩu</label>
                  <input id="confirm-pw" type="password" value={confirmNewPw}
                    onChange={(e) => setConfirmNewPw(e.target.value)}
                    placeholder="Nhập lại mật khẩu mới" style={styles.input}
                    autoComplete="new-password" />
                </div>
                {error && <motion.div style={styles.error} initial={{ opacity: 0 }} animate={{ opacity: 1 }}>{error}</motion.div>}
                <div style={styles.buttonWrapper}>
                  {loading
                    ? <div style={styles.spinnerWrapper}><LoadingSpinner size="sm" /></div>
                    : <AnimatedButton disabled={!newPw || !confirmNewPw}>Đặt lại mật khẩu</AnimatedButton>
                  }
                </div>
              </form>
            )}

            {forgotStep === 'newpw' && pwResetDone && (
              <motion.div initial={{ opacity: 0, y: -6 }} animate={{ opacity: 1, y: 0 }}>
                <div style={styles.successBox}>
                  ✅ Mật khẩu đã được đặt lại thành công!
                </div>
                <div style={{ marginTop: '16px' }}>
                  <AnimatedButton onClick={() => switchTab('login')}>Đăng nhập ngay</AnimatedButton>
                </div>
              </motion.div>
            )}
          </motion.div>
        )}
      </motion.div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  container: {
    minHeight: '100vh', display: 'flex', alignItems: 'center',
    justifyContent: 'center', padding: '24px 20px', background: 'var(--color-bg)',
  },
  formWrapper: { width: '100%', maxWidth: '380px' },
  logoArea: { textAlign: 'center', marginBottom: '24px' },
  logoGlow: {
    display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
    width: 64, height: 64, borderRadius: '50%',
    background: 'var(--color-surface)', border: '1px solid var(--color-primary)', marginBottom: 12,
  },
  logoIcon: { fontSize: '28px', color: 'var(--color-primary)' },
  title: { fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-primary)', margin: 0 },
  tabs: {
    display: 'flex', gap: '0', marginBottom: '20px',
    borderRadius: '10px', overflow: 'hidden',
    border: '1px solid var(--color-surface-light)',
  },
  tab: {
    flex: 1, padding: '10px 0', fontSize: '0.9rem', fontWeight: 600,
    background: 'var(--color-surface)', color: 'var(--color-text-secondary)',
    border: 'none', cursor: 'pointer', transition: 'all 150ms',
  },
  tabActive: {
    background: 'var(--color-primary)', color: '#0a0a0f',
  },
  divider: { display: 'flex', alignItems: 'center', gap: '12px', marginBottom: '16px' },
  dividerLine: { flex: 1, height: '1px', background: 'var(--color-surface-light)' },
  dividerText: { fontSize: '0.75rem', color: 'var(--color-text-secondary)' },
  quickSection: { marginBottom: '4px' },
  quickLabel: { fontSize: '0.8rem', color: 'var(--color-text-secondary)', textAlign: 'center', marginBottom: '10px' },
  quickButtons: { display: 'flex', flexDirection: 'column', gap: '8px' },
  quickButton: {
    width: '100%', padding: '12px 16px', background: 'var(--color-surface)',
    border: '1px solid var(--color-surface-light)', borderRadius: '10px',
    color: 'var(--color-text)', fontSize: '0.9rem', fontWeight: 500,
    cursor: 'pointer', textAlign: 'left',
  },
  form: { display: 'flex', flexDirection: 'column', gap: '16px' },
  field: { display: 'flex', flexDirection: 'column', gap: '6px' },
  label: { fontSize: '0.85rem', color: 'var(--color-text-secondary)', fontWeight: 500 },
  input: {
    background: 'var(--color-surface)', color: 'var(--color-text)',
    border: '1px solid var(--color-surface-light)', borderRadius: '8px',
    padding: '12px', fontSize: '1rem', width: '100%', boxSizing: 'border-box' as const,
  },
  passwordWrapper: { position: 'relative', display: 'flex', alignItems: 'center' },
  eyeBtn: {
    position: 'absolute', right: '12px', background: 'none', border: 'none',
    color: 'var(--color-text-secondary)', cursor: 'pointer', padding: '4px',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
  },
  error: {
    color: 'var(--color-error)', fontSize: '0.875rem', padding: '10px 12px',
    background: 'color-mix(in srgb, var(--color-error) 10%, var(--color-surface))',
    borderRadius: '8px', border: '1px solid color-mix(in srgb, var(--color-error) 25%, transparent)',
  },
  buttonWrapper: { marginTop: '4px' },
  spinnerWrapper: { display: 'flex', justifyContent: 'center', padding: '8px 0' },
  forgotLink: {
    background: 'none', border: 'none', color: 'var(--color-primary)',
    fontSize: '0.8rem', cursor: 'pointer', padding: '0', textDecoration: 'underline',
  },
  backBtn: {
    background: 'none', border: 'none', color: 'var(--color-text-secondary)',
    fontSize: '0.85rem', cursor: 'pointer', padding: '0 0 16px', display: 'block',
  },
  forgotHint: {
    fontSize: '0.875rem', color: 'var(--color-text-secondary)',
    marginBottom: '20px', lineHeight: 1.5,
  },
  successBox: {
    padding: '14px 16px', borderRadius: '10px', fontSize: '0.875rem',
    background: 'color-mix(in srgb, var(--color-success) 10%, var(--color-surface))',
    color: 'var(--color-success)',
    border: '1px solid color-mix(in srgb, var(--color-success) 25%, transparent)',
    lineHeight: 1.5,
  },
  stepRow: { display: 'flex', alignItems: 'center', marginBottom: '24px' },
  stepDot: {
    width: '28px', height: '28px', borderRadius: '50%',
    display: 'flex', alignItems: 'center', justifyContent: 'center',
    fontSize: '0.75rem', fontWeight: 700, color: '#fff', flexShrink: 0,
  },
  stepLine: { flex: 1, height: '2px', background: 'var(--color-surface-light)', minWidth: '24px' },
  resendBtn: {
    background: 'none', border: 'none', color: 'var(--color-primary)',
    fontSize: '0.82rem', cursor: 'pointer', padding: '8px 0', textAlign: 'center' as const,
    width: '100%', textDecoration: 'underline',
  },
};
