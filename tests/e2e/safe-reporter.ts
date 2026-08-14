import { rmSync } from 'node:fs'
import { basename } from 'node:path'
import type {
  FullConfig,
  FullResult,
  Reporter,
  TestCase,
  TestResult,
} from '@playwright/test/reporter'

/** CI reporter for tests that handle credentials and opaque backup material. */
export default class SafeReporter implements Reporter {
  private config?: FullConfig
  private passed = 0
  private failed = 0
  private skipped = 0

  onBegin(config: FullConfig): void {
    this.config = config
    console.log('SENSITIVE E2E START artifacts=sanitized')
  }

  onTestEnd(test: TestCase, result: TestResult): void {
    if (result.status === 'passed') this.passed += 1
    else if (result.status === 'skipped') this.skipped += 1
    else this.failed += 1
    const failureLocation = result.errors.find(error => error.location)?.location
    console.log(
      `SENSITIVE E2E CHECKPOINT completed=${this.passed + this.failed + this.skipped}`
      + ` passed=${this.passed} failed=${this.failed} skipped=${this.skipped}`
      + ` scope=${basename(test.location.file)}:${test.location.line}`
      + (failureLocation
        ? ` failure=${basename(failureLocation.file)}:${failureLocation.line}`
        : ''),
    )
  }

  onEnd(result: FullResult): void {
    // Playwright writes an error-context file even with trace/video/screenshot
    // disabled. It is useful locally but can contain application text, so the
    // sensitive output directory is always removed before CI can retain it.
    for (const project of this.config?.projects ?? []) {
      rmSync(project.outputDir, { recursive: true, force: true })
    }
    console.log(
      `SENSITIVE E2E RESULT status=${result.status}`
      + ` passed=${this.passed} failed=${this.failed} skipped=${this.skipped}`,
    )
  }
}
