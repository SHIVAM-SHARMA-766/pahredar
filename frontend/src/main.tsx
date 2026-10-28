import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { lazy, StrictMode, Suspense, type ReactNode } from 'react'
import { createRoot } from 'react-dom/client'
import { createBrowserRouter, Navigate, RouterProvider } from 'react-router'
import { Layout } from './components/Layout'
import { ErrorBox, Spinner } from './components/ui'
import './index.css'
import { CveListPage } from './pages/CveListPage'

// Pages with charts pull in Recharts; load them on first visit so the list
// view stays small.
const CveDetailPage = lazy(() => import('./pages/CveDetailPage').then((m) => ({ default: m.CveDetailPage })))
const VendorPage = lazy(() => import('./pages/VendorPage').then((m) => ({ default: m.VendorPage })))
const ProductPage = lazy(() => import('./pages/VendorPage').then((m) => ({ default: m.ProductPage })))
const VendorsPage = lazy(() => import('./pages/VendorsPage').then((m) => ({ default: m.VendorsPage })))
const SyncPage = lazy(() => import('./pages/SyncPage').then((m) => ({ default: m.SyncPage })))

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
      // The dashboard (milestone 5) will live at "/"; until then it opens the list.
      { index: true, element: <Navigate to="/cves" replace /> },
      { path: 'cves', element: <CveListPage /> },
      { path: 'cves/:id', element: page(<CveDetailPage />) },
      { path: 'vendors', element: page(<VendorsPage />) },
      { path: 'vendors/:vendor', element: page(<VendorPage />) },
      { path: 'vendors/:vendor/products/:product', element: page(<ProductPage />) },
      { path: 'sync', element: page(<SyncPage />) },
      { path: '*', element: <ErrorBox error="Page not found." /> },
    ],
  },
])

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <QueryClientProvider client={queryClient}>
      <RouterProvider router={router} />
    </QueryClientProvider>
  </StrictMode>,
)
