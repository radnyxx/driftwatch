// Sample Notes v1.0.0 (demo fixture)
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({ notes: [] });
});
