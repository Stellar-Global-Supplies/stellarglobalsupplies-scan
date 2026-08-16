import { StrictMode } from 'react';
import { createRoot }  from 'react-dom/client';
import App from './App';

/* ── Global reset & Stellar Global Supplies brand tokens ──────────────────── */
const style = document.createElement('style');
style.textContent = `
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    /* Stellar Global Supplies brand palette */
    --sgs-navy:       #1B3A6B;   /* primary brand blue */
    --sgs-navy-light: #2A52A0;
    --sgs-gold:       #C8990A;   /* accent */
    --sgs-gold-light: #F0C93A;
    --sgs-dark:       #1a1a18;
    --sgs-bg:         #F5F5F0;
    --sgs-surface:    #FFFFFF;
    --sgs-border:     #E8E8E0;
    --sgs-text:       #1a1a18;
    --sgs-muted:      #888880;

    /* Severity */
    --sev-critical: #E24B4A;
    --sev-high:     #EF9F27;
    --sev-medium:   #639922;
    --sev-low:      #378ADD;
  }

  html, body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Helvetica, Arial, sans-serif;
    font-size:   15px;
    background:  var(--sgs-bg);
    color:       var(--sgs-text);
    min-height:  100vh;
    -webkit-font-smoothing: antialiased;
  }

  button { font-family: inherit; }
  a      { color: var(--sgs-navy); }

  /* Scrollbar */
  ::-webkit-scrollbar       { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: #ddd; border-radius: 3px; }
`;
document.head.appendChild(style);

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>
);
