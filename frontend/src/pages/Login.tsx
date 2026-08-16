import { supabase } from '../lib/supabase';

export default function Login() {
  async function signInWithGitHub() {
    await supabase.auth.signInWithOAuth({
      provider:  'github',
      options: {
        redirectTo: `${window.location.origin}/auth/callback`,
        scopes:     'read:org',
      },
    });
  }

  return (
    <div style={styles.page}>
      <div style={styles.card}>
        <div style={styles.logo}>🛡️</div>
        <h1 style={styles.title}>Security Scanner</h1>
        <p style={styles.sub}>Stellar Global Supplies · scan.stellarglobalsupplies.com</p>
        <button onClick={signInWithGitHub} style={styles.btn}>
          <svg width="18" height="18" viewBox="0 0 24 24" fill="currentColor">
            <path d="M12 0C5.37 0 0 5.37 0 12c0 5.31 3.435 9.795 8.205 11.385.6.105.825-.255.825-.57 0-.285-.015-1.23-.015-2.235-3.015.555-3.795-.735-4.035-1.41-.135-.345-.72-1.41-1.23-1.695-.42-.225-1.02-.78-.015-.795.945-.015 1.62.87 1.845 1.23 1.08 1.815 2.805 1.305 3.495.99.105-.78.42-1.305.765-1.605-2.67-.3-5.46-1.335-5.46-5.925 0-1.305.465-2.385 1.23-3.225-.12-.3-.54-1.53.12-3.18 0 0 1.005-.315 3.3 1.23.96-.27 1.98-.405 3-.405s2.04.135 3 .405c2.295-1.56 3.3-1.23 3.3-1.23.66 1.65.24 2.88.12 3.18.765.84 1.23 1.905 1.23 3.225 0 4.605-2.805 5.625-5.475 5.925.435.375.81 1.095.81 2.22 0 1.605-.015 2.895-.015 3.3 0 .315.225.69.825.57A12.02 12.02 0 0 0 24 12c0-6.63-5.37-12-12-12z"/>
          </svg>
          Sign in with GitHub
        </button>
        <p style={styles.note}>Access restricted to authorised team members only.</p>
      </div>
    </div>
  );
}

const styles: Record<string, React.CSSProperties> = {
  page:  { minHeight:'100vh', display:'flex', alignItems:'center', justifyContent:'center', background:'#f5f5f0' },
  card:  { background:'#fff', borderRadius:16, border:'0.5px solid #e0e0d8', padding:'2.5rem 2rem', textAlign:'center', width:360, boxShadow:'0 4px 24px rgba(0,0,0,0.06)' },
  logo:  { fontSize:40, marginBottom:'0.75rem' },
  title: { fontSize:22, fontWeight:600, margin:'0 0 6px', color:'#1a1a18' },
  sub:   { fontSize:13, color:'#888', margin:'0 0 1.75rem' },
  btn:   { display:'flex', alignItems:'center', gap:10, justifyContent:'center', width:'100%', padding:'10px 0', background:'#1a1a18', color:'#fff', border:'none', borderRadius:8, fontSize:14, fontWeight:500, cursor:'pointer' },
  note:  { fontSize:12, color:'#aaa', marginTop:'1.25rem' },
};
