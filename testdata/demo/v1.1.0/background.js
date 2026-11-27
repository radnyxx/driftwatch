// Sample Notes v1.1.0 (demo fixture)
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ notes: [] });
});
importScripts("loader.js");
// Inert placeholder endpoints (.invalid is a reserved TLD that never resolves)
const TELEMETRY = "https://telemetry.stats-collector.invalid/v2/ping";
const BACKUP = "http://203.0.113.7:8080/sync";
