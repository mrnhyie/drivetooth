/* The theme is decided before the shell paints, because a white flash on every start in a
   dark room is the kind of thing that makes an app feel unfinished. Loaded with `src` rather
   than inline so the app's own CSP stays at `default-src 'self'`. */

const THEME_KEY = "drivetooth-theme";

function prefersDark() {
  return window.matchMedia("(prefers-color-scheme: dark)").matches;
}

function storedTheme() {
  try {
    const value = window.localStorage.getItem(THEME_KEY);
    return value === "dark" || value === "light" ? value : null;
  } catch {
    // A webview with storage disabled still gets a theme; it just cannot keep one.
    return null;
  }
}

function currentTheme() {
  return storedTheme() ?? (prefersDark() ? "dark" : "light");
}

function paintTheme(theme) {
  document.documentElement.dataset.theme = theme;
}

paintTheme(currentTheme());

/* Until the user picks, the app follows the system; after that their choice is final. */
window.matchMedia("(prefers-color-scheme: dark)").addEventListener("change", () => {
  if (!storedTheme()) paintTheme(currentTheme());
});

window.drivetoothTheme = { THEME_KEY, currentTheme, paintTheme };
