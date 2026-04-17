import { useState, useEffect } from 'react';
import { Outlet, useLocation } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { AlertTriangle, WifiOff } from 'lucide-react';
import { Sidebar } from './Sidebar';
import { Header } from './Header';
import { ToastContainer } from '../ui/Toast';
import { useToast } from '../../hooks/useToast';
import { checkBackendOnline } from '../../api/client';

const PAGE_CONFIG: Record<string, { title: string; breadcrumbs: Array<{ label: string }> }> = {
  '/': { title: 'Dashboard', breadcrumbs: [{ label: 'Monitor' }, { label: 'Dashboard' }] },
  '/emails': { title: 'Email Inbox', breadcrumbs: [{ label: 'Monitor' }, { label: 'Email Inbox' }] },
  '/active-scans': { title: 'Active Scans', breadcrumbs: [{ label: 'Monitor' }, { label: 'Active Scans' }] },
  '/scans': { title: 'Scan Results', breadcrumbs: [{ label: 'Analyze' }, { label: 'Scan Results' }] },
  '/url-analysis': { title: 'URL Analysis', breadcrumbs: [{ label: 'Analyze' }, { label: 'URL Analysis' }] },
  '/attachments': { title: 'Attachments', breadcrumbs: [{ label: 'Analyze' }, { label: 'Attachments' }] },
  '/health': { title: 'API Health', breadcrumbs: [{ label: 'System' }, { label: 'API Health' }] },
  '/settings': { title: 'Settings', breadcrumbs: [{ label: 'System' }, { label: 'Settings' }] },
};

export function Layout() {
  const location = useLocation();
  const [backendOnline, setBackendOnline] = useState<boolean | null>(null);
  const [refreshKey, setRefreshKey] = useState(0);
  const { toasts, toast, removeToast } = useToast();

  // Find current page config (handle dynamic routes like /scans/:id)
  const pathKey = Object.keys(PAGE_CONFIG).find(
    (k) => location.pathname === k || (k !== '/' && location.pathname.startsWith(k + '/'))
  ) ?? '/';
  const pageConf = PAGE_CONFIG[pathKey] ?? PAGE_CONFIG['/'];

  useEffect(() => {
    let mounted = true;
    const check = async () => {
      const online = await checkBackendOnline();
      if (mounted) setBackendOnline(online);
    };
    check();
    const id = setInterval(check, 30000);
    return () => { mounted = false; clearInterval(id); };
  }, []);

  const handleEmailsFetched = () => setRefreshKey((k) => k + 1);

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden', background: 'var(--bg-page)' }}>
      <Sidebar apiStatus={backendOnline === false ? 'offline' : 'online'} />

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {/* Backend Offline Banner */}
        <AnimatePresence>
          {backendOnline === false && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: 36, opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              style={{
                background: 'var(--danger-subtle)',
                borderBottom: '1px solid var(--danger)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 8,
                overflow: 'hidden',
              }}
            >
              <WifiOff size={14} style={{ color: 'var(--danger)' }} />
              <span style={{ fontSize: '0.8rem', color: 'var(--text-danger)', fontWeight: 600 }}>
                Backend Offline — API at http://127.0.0.1:8080 is not responding
              </span>
            </motion.div>
          )}
        </AnimatePresence>

        <Header
          title={pageConf.title}
          breadcrumbs={pageConf.breadcrumbs}
          onEmailsFetched={handleEmailsFetched}
          toast={toast.success}
          toastError={toast.error}
        />

        <main style={{ flex: 1, overflow: 'auto', background: 'var(--bg-page)' }}>
          <AnimatePresence mode="wait">
            <motion.div
              key={location.pathname}
              initial={{ opacity: 0, x: 20 }}
              animate={{ opacity: 1, x: 0 }}
              exit={{ opacity: 0, x: -10 }}
              transition={{ duration: 0.2, ease: 'easeOut' }}
              style={{ height: '100%' }}
            >
              <Outlet context={{ refreshKey, toast }} />
            </motion.div>
          </AnimatePresence>
        </main>
      </div>

      <ToastContainer toasts={toasts} removeToast={removeToast} />
    </div>
  );
}
