import { Component, type ReactNode } from 'react'
import { Button } from '@/components/ui/button'

interface Props { children?: ReactNode }
interface State { error: Error | null }

export default class RouteErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  render() {
    if (this.state.error) {
      return (
        <div className="flex min-h-screen items-center justify-center p-8">
          <div className="max-w-md text-center space-y-4">
            <h2 className="text-xl font-semibold text-foreground">Something went wrong</h2>
            <p className="text-sm text-muted-foreground">{this.state.error.message}</p>
            <Button onClick={() => this.setState({ error: null })}>Try again</Button>
          </div>
        </div>
      )
    }
    return this.props.children
  }
}
