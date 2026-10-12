import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import './styles/index.css';

// Looping animations repaint the blurred glass panels every frame; stop them while the user is elsewhere.
function syncInactive() {
  document.documentElement.toggleAttribute('data-inactive', document.hidden || !document.hasFocus());
}
window.addEventListener('focus', syncInactive);
window.addEventListener('blur', syncInactive);
document.addEventListener('visibilitychange', syncInactive);
syncInactive();

ReactDOM.createRoot(document.getElementById('root') as HTMLElement).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
