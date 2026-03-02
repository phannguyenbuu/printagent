/**
 * Email templates for authentication flows.
 * Returns { subject, html, text } ready to pass to any email provider (SendGrid, SES, Resend, etc.)
 */

export interface EmailTemplate {
  subject: string;
  html: string;
  text: string;
}

const APP_NAME = 'Quản lý Sửa chữa Máy móc';
const SUPPORT_EMAIL = 'support@goxprint.vn';

// ---------------------------------------------------------------------------
// Welcome / Registration
// ---------------------------------------------------------------------------
export function getWelcomeEmailTemplate(params: {
  fullName: string;
  email: string;
  loginUrl: string;
}): EmailTemplate {
  const { fullName, email, loginUrl } = params;
  return {
    subject: `Chào mừng bạn đến với ${APP_NAME}!`,
    html: `
<!DOCTYPE html>
<html lang="vi">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:Arial,sans-serif;color:#e0e0e0;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 20px;">
      <table width="100%" style="max-width:480px;background:#12121a;border-radius:16px;border:1px solid #1e1e2e;overflow:hidden;">
        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#00d4ff,#7b2fff);padding:32px;text-align:center;">
          <div style="font-size:40px;">⚙️</div>
          <h1 style="margin:12px 0 0;font-size:1.3rem;color:#fff;">${APP_NAME}</h1>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:32px;">
          <h2 style="margin:0 0 16px;font-size:1.1rem;color:#00d4ff;">Xin chào, ${fullName}!</h2>
          <p style="margin:0 0 16px;line-height:1.6;color:#a0a0b0;">
            Tài khoản của bạn đã được tạo thành công với email <strong style="color:#e0e0e0;">${email}</strong>.
          </p>
          <p style="margin:0 0 24px;line-height:1.6;color:#a0a0b0;">
            Bạn có thể đăng nhập ngay để bắt đầu quản lý yêu cầu sửa chữa máy móc.
          </p>
          <div style="text-align:center;">
            <a href="${loginUrl}" style="display:inline-block;padding:14px 32px;background:linear-gradient(135deg,#00d4ff,#7b2fff);color:#0a0a0f;font-weight:700;border-radius:10px;text-decoration:none;font-size:0.95rem;">
              Đăng nhập ngay
            </a>
          </div>
        </td></tr>
        <!-- Footer -->
        <tr><td style="padding:20px 32px;border-top:1px solid #1e1e2e;text-align:center;">
          <p style="margin:0;font-size:0.75rem;color:#606070;">
            Nếu bạn không tạo tài khoản này, hãy bỏ qua email này hoặc liên hệ
            <a href="mailto:${SUPPORT_EMAIL}" style="color:#00d4ff;">${SUPPORT_EMAIL}</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
    text: `Xin chào ${fullName},\n\nTài khoản của bạn đã được tạo thành công với email ${email}.\n\nĐăng nhập tại: ${loginUrl}\n\nNếu bạn không tạo tài khoản này, hãy liên hệ ${SUPPORT_EMAIL}.`,
  };
}

// ---------------------------------------------------------------------------
// Forgot Password / OTP Reset
// ---------------------------------------------------------------------------
export function getForgotPasswordEmailTemplate(params: {
  fullName: string;
  email: string;
  otpCode: string;
  expiresInMinutes?: number;
}): EmailTemplate {
  const { fullName, email, otpCode, expiresInMinutes = 10 } = params;
  return {
    subject: `[${APP_NAME}] Mã xác nhận đặt lại mật khẩu: ${otpCode}`,
    html: `
<!DOCTYPE html>
<html lang="vi">
<head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#0a0a0f;font-family:Arial,sans-serif;color:#e0e0e0;">
  <table width="100%" cellpadding="0" cellspacing="0">
    <tr><td align="center" style="padding:40px 20px;">
      <table width="100%" style="max-width:480px;background:#12121a;border-radius:16px;border:1px solid #1e1e2e;overflow:hidden;">
        <!-- Header -->
        <tr><td style="background:linear-gradient(135deg,#ff6b35,#f7c59f);padding:32px;text-align:center;">
          <div style="font-size:40px;">🔑</div>
          <h1 style="margin:12px 0 0;font-size:1.3rem;color:#0a0a0f;">${APP_NAME}</h1>
        </td></tr>
        <!-- Body -->
        <tr><td style="padding:32px;">
          <h2 style="margin:0 0 16px;font-size:1.1rem;color:#ff6b35;">Đặt lại mật khẩu</h2>
          <p style="margin:0 0 16px;line-height:1.6;color:#a0a0b0;">
            Xin chào <strong style="color:#e0e0e0;">${fullName}</strong>,
          </p>
          <p style="margin:0 0 24px;line-height:1.6;color:#a0a0b0;">
            Chúng tôi nhận được yêu cầu đặt lại mật khẩu cho tài khoản
            <strong style="color:#e0e0e0;">${email}</strong>.
            Sử dụng mã bên dưới để xác nhận. Mã có hiệu lực trong
            <strong style="color:#e0e0e0;">${expiresInMinutes} phút</strong>.
          </p>
          <!-- OTP Box -->
          <div style="text-align:center;margin:28px 0;">
            <div style="display:inline-block;padding:20px 40px;background:#1e1e2e;border-radius:14px;border:2px solid #ff6b35;">
              <span style="font-size:2.2rem;font-weight:900;letter-spacing:0.35em;color:#ff6b35;font-family:monospace;">
                ${otpCode}
              </span>
            </div>
          </div>
          <p style="margin:0;line-height:1.6;color:#606070;font-size:0.8rem;text-align:center;">
            Không chia sẻ mã này với bất kỳ ai.
          </p>
        </td></tr>
        <!-- Warning -->
        <tr><td style="padding:16px 32px;background:#1a1a0a;border-top:1px solid #2e2e1e;">
          <p style="margin:0;font-size:0.78rem;color:#806040;line-height:1.5;">
            ⚠️ Nếu bạn không yêu cầu đặt lại mật khẩu, hãy bỏ qua email này. Mật khẩu của bạn sẽ không thay đổi.
          </p>
        </td></tr>
        <!-- Footer -->
        <tr><td style="padding:20px 32px;border-top:1px solid #1e1e2e;text-align:center;">
          <p style="margin:0;font-size:0.75rem;color:#606070;">
            Hỗ trợ: <a href="mailto:${SUPPORT_EMAIL}" style="color:#00d4ff;">${SUPPORT_EMAIL}</a>
          </p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body>
</html>`,
    text: `Xin chào ${fullName},\n\nMã xác nhận đặt lại mật khẩu của bạn là:\n\n  ${otpCode}\n\nMã có hiệu lực trong ${expiresInMinutes} phút. Không chia sẻ mã này với bất kỳ ai.\n\nNếu bạn không yêu cầu, hãy bỏ qua email này.\n\nHỗ trợ: ${SUPPORT_EMAIL}`,
  };
}
