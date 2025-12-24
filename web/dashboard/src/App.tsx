import { Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'
import Overview from './pages/Overview'
import RoutesPage from './pages/Routes'
import Upstreams from './pages/Upstreams'

function App() {
  return (
    <Routes>
      <Route path="/" element={<Layout />}>
        <Route index element={<Overview />} />
        <Route path="routes" element={<RoutesPage />} />
        <Route path="upstreams" element={<Upstreams />} />
      </Route>
    </Routes>
  )
}

export default App
