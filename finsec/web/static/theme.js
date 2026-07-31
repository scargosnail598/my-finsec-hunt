"use strict";

(() => {
  const storageKey = "finsec-theme";
  const allowedPreferences = new Set(["light", "dark"]);
  let preference = "system";

  try {
    const savedPreference = window.localStorage.getItem(storageKey);
    if (allowedPreferences.has(savedPreference)) preference = savedPreference;
  } catch {
    // Storage can be unavailable in hardened or private browser contexts.
  }

  const systemTheme = window.matchMedia("(prefers-color-scheme: dark)").matches
    ? "dark"
    : "light";
  document.documentElement.dataset.theme = preference === "system" ? systemTheme : preference;
  document.documentElement.dataset.themePreference = preference;
})();
