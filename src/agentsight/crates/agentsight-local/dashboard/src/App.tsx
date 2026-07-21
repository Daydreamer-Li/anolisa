import React from 'react';
import { HashRouter, Routes, Route } from 'react-router-dom';
import { NavBar } from './components/NavBar';
import { LocalSessions } from './pages/LocalSessions';
import { AtifViewerPage } from './pages/AtifViewerPage';

const App: React.FC = () => {
  return (
    <HashRouter>
      <div className="min-h-screen bg-gray-50 flex flex-col">
        <NavBar />
        <main className="flex-1 overflow-auto">
          <Routes>
            <Route path="/" element={<LocalSessions />} />
            <Route path="/atif" element={<AtifViewerPage />} />
          </Routes>
        </main>
      </div>
    </HashRouter>
  );
};

export default App;
