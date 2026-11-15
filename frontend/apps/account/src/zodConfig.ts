import { z } from 'zod'

// zod compiles object parsers with `new Function` when it can, and to find
// out it tries one; the app's Content-Security-Policy has no 'unsafe-eval'
// (docs/content-security-policy.md), so the try would only be reported and
// fail. Imported first in main.tsx: zod reads this when a schema is made.
z.config({ jitless: true })
