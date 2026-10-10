#!/usr/bin/env bash
# Measures the chat search index in a real browser: an encrypted IndexedDB
# store filled with a fixed workload (kutup-chat-core `search::bench`, the
# same as the native `search::tests::scale`), timed in headless Chromium.
#
#   scripts/bench-search-index.sh            # 50,000 messages
#   scripts/bench-search-index.sh 10000      # another count
#
# Needs wasm-bindgen 0.2.126, and the e2e suite's Playwright installed
# (tests/e2e: npm ci && npx playwright install chromium).
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
count="${1:-50000}"
work="$(mktemp -d)"
trap 'kill "${server:-0}" 2>/dev/null || true; rm -rf "$work"' EXIT

cargo build --quiet \
  --manifest-path "$root/crates/kutup-chat-core/Cargo.toml" \
  --profile wasm-release --target wasm32-unknown-unknown \
  --no-default-features --features bench
wasm-bindgen \
  "$root/crates/kutup-chat-core/target/wasm32-unknown-unknown/wasm-release/kutup_chat_core.wasm" \
  --target web --out-dir "$work" --out-name bench

cat > "$work/index.html" <<'HTML'
<!doctype html>
<meta charset="utf-8">
<script type="module">
  import init, { benchSearchIndex } from './bench.js'
  window.runBench = async (count) => {
    await init()
    return benchSearchIndex(`bench-${Date.now()}`, count)
  }
  window.benchReady = true
</script>
HTML

port="$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
python3 -m http.server "$port" --bind 127.0.0.1 --directory "$work" >/dev/null 2>&1 &
server=$!
sleep 1

cd "$root/tests/e2e"
COUNT="$count" URL="http://127.0.0.1:$port/" node --input-type=module -e '
  import { chromium } from "@playwright/test"
  const browser = await chromium.launch()
  const page = await browser.newPage()
  await page.goto(process.env.URL)
  await page.waitForFunction(() => window.benchReady === true)
  const report = await page.evaluate((count) => window.runBench(count), Number(process.env.COUNT))
  console.log(JSON.stringify(report, null, 2))
  await browser.close()
'
