import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { lazy, StrictMode, Suspense, type ReactNode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, RouterProvider } from 'react-router'
import { LoginModal } from './components/LoginModal'
import { Layout } from './components/Layout'
import { AuthProvider } from './lib/auth'
import { ErrorBox, Spinner } from './components/ui'
import './index.css'
import { CveListPage } from './pages/CveListPage'

// Pages with charts pull in Recharts; load them on first visit so the list
// view stays small.
const CveDetailPage = lazy(() => import('./pages/CveDetailPage').then((m) => ({ default: m.CveDetailPage })))
const VendorPage = lazy(() => import('./pages/VendorPage').then((m) => ({ default: m.VendorPage })))
const ProductPage = lazy(() => import('./pages/VendorPage').then((m) => ({ default: m.ProductPage })))
const VendorsPage = lazy(() => import('./pages/VendorsPage').then((m) => ({ default: m.VendorsPage })))
const DashboardPage = lazy(() => import('./pages/DashboardPage').then((m) => ({ default: m.DashboardPage })))
const NewsPage = lazy(() => import('./pages/NewsPage').then((m) => ({ default: m.NewsPage })))
const ScanPage = lazy(() => import('./pages/ScanPage').then((m) => ({ default: m.ScanPage })))
const AssetsPage = lazy(() => import('./pages/AssetsPage').then((m) => ({ default: m.AssetsPage })))
const AssetDetailPage = lazy(() => import('./pages/AssetDetailPage').then((m) => ({ default: m.AssetDetailPage })))
const IncidentsPage = lazy(() => import('./pages/IncidentsPage').then((m) => ({ default: m.IncidentsPage })))
const SyncPage = lazy(() => import('./pages/SyncPage').then((m) => ({ default: m.SyncPage })))
const UsersPage = lazy(() => import('./pages/UsersPage').then((m) => ({ default: m.UsersPage })))
const ClientsPage = lazy(() => import('./pages/ClientsPage').then((m) => ({ default: m.ClientsPage })))
const NotificationsPage = lazy(() => import('./pages/NotificationsPage').then((m) => ({ default: m.NotificationsPage })))

const page = (el: ReactNode) => <Suspense fallback={<Spinner />}>{el}</Suspense>

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 60_000,
      retry: (failures, error) => failures < 2 && !('status' in error && (error.status === 400 || error.status === 404)),
      refetchOnWindowFocus: false,
    },
  },
})

const router = createBrowserRouter([
  {
    element: <Layout />,
    children: [
      { index: true, element: page(<DashboardPage />) },
      { path: 'cves', element: <CveListPage /> },
      { path: 'cves/:id', element: page(<CveDetailPage />) },
      { path: 'vendors', element: page(<VendorsPage />) },
      { path: 'vendors/:vendor', element: page(<VendorPage />) },
      { path: 'vendors/:vendor/products/:product', element: page(<ProductPage />) },
      { path: 'news', element: page(<NewsPage />) },
      { path: 'scan', element: page(<ScanPage />) },
      { path: 'inventory', element: page(<AssetsPage />) },
      { path: 'inventory/:id', element: page(<AssetDetailPage />) },
      { path: 'incidents', element: page(<IncidentsPage />) },
      { path: 'notifications', element: page(<NotificationsPage />) },
      { path: 'sync', element: page(<SyncPage />) },
      { path: 'users', element: page(<UsersPage />) },
      { path: 'clients', element: page(<ClientsPage />) },
      { path: '*', element: <ErrorBox error="Page not found." /> },
    ],
  },
])

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <AuthProvider>
        <RouterProvider router={router} />
        <LoginModal />
      </AuthProvider>
    </QueryClientProvider>
  </StrictMode>,
)
