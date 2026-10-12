// No-flash theme: mirror next-themes (storage key kutup-theme) before first
// paint. A stored light/dark wins; otherwise follow the OS. A file, not inline:
// Pass's policy allows no inline script.
;(function () {
  var p
  try {
    p = localStorage.getItem('kutup-theme')
  } catch (e) {}
  var dark = p === 'dark' || (p !== 'light' && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.classList.add(dark ? 'dark' : 'light')
  document.documentElement.style.colorScheme = dark ? 'dark' : 'light'
})()
