import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App';
import { ConfirmProvider, ErrorBoundary, ToastProvider } from './components/ui';
import { I18nProvider } from './i18n';
import { SettingsProvider, useSettings } from './settings';
// Brand typefaces are bundled with the app (no network font loading).
import '@fontsource-variable/inter';
import '@fontsource-variable/space-grotesk';
import '@fontsource-variable/jetbrains-mono';
import './index.css';

function Localized({ children }: { children: React.ReactNode }) {
  const { settings } = useSettings();
  return (
    <I18nProvider lang={settings.language}>
      <ToastProvider>
        <ConfirmProvider>{children}</ConfirmProvider>
      </ToastProvider>
    </I18nProvider>
  );
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <ErrorBoundary>
      <SettingsProvider>
        <Localized>
          <App />
        </Localized>
      </SettingsProvider>
    </ErrorBoundary>
  </React.StrictMode>,
);
