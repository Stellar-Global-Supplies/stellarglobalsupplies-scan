import { useEffect } from 'react';

const LANDING_URL = (import.meta.env.VITE_LANDING_URL as string) || 'https://apps.stellarglobalsupplies.com';

export default function Login() {
  useEffect(() => {
    const callback = encodeURIComponent(window.location.origin + '/dashboard');
    window.location.replace(`${LANDING_URL}/login?callback=${callback}`);
  }, []);

  return (
    <div style={{ minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center', background:'#f5f5f0' }}>
      <div style={{ textAlign:'center' }}>
        <div style={{ fontSize:32, marginBottom:12 }}>🛡️</div>
        <p style={{ color:'#888', fontSize:14 }}>Redirecting to portal…</p>
      </div>
    </div>
  );
}
