import { Component, type ReactNode, type ErrorInfo } from 'react'

interface Props {
  children: ReactNode
}
interface State {
  error: Error | null
  componentStack: string
}

/**
 * Top-level error boundary.
 *
 * Without one, a render-time throw anywhere in the React tree — most
 * dangerously in the unprotected routes (`/`, `/server-select`, `/login`),
 * which had no boundary at all — unmounts the whole root and leaves a blank
 * white window with nothing surfaced (React 18 logs to `console.error` and
 * stops, no `window.onerror`). On the desktop there's no usable devtools,
 * so "blank white window" was an undiagnosable failure mode.
 *
 * This catches the throw, logs it (so devtools / a console capture still see
 * it), and renders the error message + stacks in a self-contained block
 * using *inline styles only* — so it works even when the crash is CSS- or
 * theme-related.
 */
export default class AppErrorBoundary extends Component<Props, State> {
  state: State = { error: null, componentStack: '' }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    this.setState({ componentStack: info.componentStack ?? '' })
    // eslint-disable-next-line no-console
    console.error('AppErrorBoundary caught:', error, info.componentStack)
  }

  render() {
    const { error, componentStack } = this.state
    if (!error) return this.props.children

    return (
      <div
        style={{
          padding: 24,
          fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace',
          fontSize: 13,
          lineHeight: 1.5,
          color: '#d4ecf7',
          background: '#060d14',
          minHeight: '100vh',
          whiteSpace: 'pre-wrap',
          wordBreak: 'break-word',
        }}
      >
        <strong style={{ color: '#f87171', fontSize: 15 }}>
          Kutup crashed while rendering
        </strong>
        {'\n\n'}
        {error.message || String(error)}
        {error.stack ? '\n\n' + error.stack : ''}
        {componentStack ? '\n\nComponent stack:' + componentStack : ''}
        {'\n\n'}
        <button
          type="button"
          onClick={() => window.location.reload()}
          style={{
            padding: '6px 12px',
            fontFamily: 'inherit',
            cursor: 'pointer',
            display: 'inline-block',
          }}
        >
          Reload
        </button>
      </div>
    )
  }
}
