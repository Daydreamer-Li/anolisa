import React from 'react';
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter } from 'react-router-dom';

// Mock heavy page components to avoid pulling in all their deps
vi.mock('../pages/ConversationList', () => ({
  ConversationList: () => <div data-testid="page-conversations">ConversationList</div>,
}));
vi.mock('../pages/AgentDashboardPage', () => ({
  AgentDashboardPage: () => <div data-testid="page-agents">AgentDashboardPage</div>,
}));
vi.mock('../pages/TokenSavingsPage', () => ({
  TokenSavingsPage: () => <div data-testid="page-savings">TokenSavingsPage</div>,
}));
vi.mock('../pages/AtifViewerPage', () => ({
  AtifViewerPage: () => <div data-testid="page-atif">AtifViewerPage</div>,
}));
vi.mock('../pages/SecurityObservabilityPage', () => ({
  SecurityObservabilityPage: () => <div data-testid="page-security">SecurityObservabilityPage</div>,
}));

import App from '../App';

afterEach(() => {
  window.location.hash = '';
});

describe('App', () => {
  it('should render NavBar with brand', () => {
    render(
      <App />
    );
    expect(screen.getByText('AgentSight')).toBeInTheDocument();
  });

  it('should render ConversationList on root path', () => {
    render(<App />);
    expect(screen.getByTestId('page-conversations')).toBeInTheDocument();
  });

  it('should render SecurityObservabilityPage on security path', () => {
    window.location.hash = '#/security';
    render(<App />);
    expect(screen.getByTestId('page-security')).toBeInTheDocument();
  });
});
