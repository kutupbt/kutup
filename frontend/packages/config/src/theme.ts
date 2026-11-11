/**
 * The no-flash theme script every app page loads before its first paint, as
 * a file (`/theme.js`, served and emitted by the shared Vite config): the
 * apps' policy allows no inline script (docs/content-security-policy.md).
 * It mirrors next-themes (storage key `kutup-theme`): a stored light or dark
 * wins; otherwise the page follows the system.
 */
export const THEME_SCRIPT = `(function () {
  var p
  try {
    p = localStorage.getItem('kutup-theme')
  } catch (e) {}
  var dark = p === 'dark' || (p !== 'light' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.classList.add(dark ? 'dark' : 'light')
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
})()
`
