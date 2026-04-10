import re

with open('app-gox/src/main.tsx', 'r', encoding='utf-8') as f:
    s1 = f.read()

s1 = re.sub(r'const GOOGLE_CLIENT_ID = .*?;', 'const GOOGLE_CLIENT_ID = import.meta.env.VITE_GOOGLE_CLIENT_ID || "";', s1)
# Remove the old strict mode and provider wrapping App
s1 = re.sub(
    r'<React\.StrictMode>[\s\S]*?<GoogleOAuthProvider clientId=\{GOOGLE_CLIENT_ID\}>[\s\S]*?<App />[\s\S]*?</GoogleOAuthProvider>[\s\S]*?</React\.StrictMode>',
    '<React.StrictMode>\n    {GOOGLE_CLIENT_ID ? (\n      <GoogleOAuthProvider clientId={GOOGLE_CLIENT_ID}>\n        <App />\n      </GoogleOAuthProvider>\n    ) : (\n      <App />\n    )}\n  </React.StrictMode>',
    s1
)

with open('app-gox/src/main.tsx', 'w', encoding='utf-8') as f:
    f.write(s1)

with open('app-gox/src/pages/LoginPage.tsx', 'r', encoding='utf-8') as f:
    s2 = f.read()

s2 = re.sub(
    r'<GoogleLogin[\s\S]*?/>',
    r'{import.meta.env.VITE_GOOGLE_CLIENT_ID && <GoogleLogin onSuccess={handleGoogleSuccess} onError={() => setError("Google Login Failed")} useOneTap theme="filled_blue" shape="pill" text={tab === "login" ? "signin_with" : "signup_with"} width="380" />}',
    s2
)

with open('app-gox/src/pages/LoginPage.tsx', 'w', encoding='utf-8') as f:
    f.write(s2)

print('Google Login patched successfully')
