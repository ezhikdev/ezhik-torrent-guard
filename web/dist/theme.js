// Applied before first paint (external file: the panel CSP forbids inline scripts).
try {
  var t = localStorage.getItem('ezhik-theme');
  if (!t) t = matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  document.documentElement.dataset.theme = t;
} catch (e) {
  document.documentElement.dataset.theme = 'dark';
}
