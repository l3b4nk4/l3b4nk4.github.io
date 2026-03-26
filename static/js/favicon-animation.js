(() => {
  const frameDelays = [
    1000,
    1000,
    1000,
    1000,
    1000,
    1000,
    1000,
    1000,
    1000,
    1000,
    1000,
    1000,
    50,
    50,
  ];

  let timerId = 0;
  let frameIndex = 0;

  const getPrimaryFavicon = () => document.getElementById("site-favicon");

  const getVersion = () => {
    const primary = getPrimaryFavicon();
    return primary instanceof HTMLLinkElement
      ? primary.dataset.faviconVersion || ""
      : "";
  };

  const getFrameCount = () => {
    const primary = getPrimaryFavicon();
    if (!(primary instanceof HTMLLinkElement)) return 0;

    const count = Number(primary.dataset.faviconFrames || "0");
    return Number.isFinite(count) ? count : 0;
  };

  const getBaseUrl = () => {
    if (window.siteConfig && typeof window.siteConfig.base === "string") {
      return window.siteConfig.base;
    }

    return `${window.location.origin}/`;
  };

  const buildAssetUrl = (path) => {
    const url = new URL(path, getBaseUrl());
    const version = getVersion();

    if (version) {
      url.searchParams.set("v", version);
    }

    return url.toString();
  };

  const getFrameUrl = (index) =>
    buildAssetUrl(`favicon-frames/frame-${String(index).padStart(2, "0")}.png`);

  const getFaviconLinks = () =>
    Array.from(
      document.querySelectorAll('link[data-favicon-slot="primary"]'),
    ).filter((node) => node instanceof HTMLLinkElement);

  const setAnimatedFrame = (index) => {
    const frameUrl = getFrameUrl(index);

    for (const link of getFaviconLinks()) {
      link.href = frameUrl;

      if (link.id !== "site-shortcut-icon") {
        link.type = "image/png";
      }
    }
  };

  const restoreStaticFavicons = () => {
    const primary = document.getElementById("site-favicon");
    if (primary instanceof HTMLLinkElement) {
      primary.href = buildAssetUrl("favicon.gif");
      primary.type = "image/gif";
    }

    const shortcut = document.getElementById("site-shortcut-icon");
    if (shortcut instanceof HTMLLinkElement) {
      shortcut.href = buildAssetUrl("favicon.ico");
    }

    const png = document.getElementById("site-png-favicon");
    if (png instanceof HTMLLinkElement) {
      png.href = buildAssetUrl("favicon.png");
      png.type = "image/png";
    }
  };

  const stopAnimation = () => {
    if (timerId) {
      window.clearTimeout(timerId);
      timerId = 0;
    }

    restoreStaticFavicons();
  };

  const tick = () => {
    const frameCount = getFrameCount();
    if (frameCount < 2) return;

    setAnimatedFrame(frameIndex);

    const delay = frameDelays[frameIndex] || 100;
    frameIndex = (frameIndex + 1) % frameCount;
    timerId = window.setTimeout(tick, delay);
  };

  const startAnimation = () => {
    stopAnimation();

    if (document.hidden || getFrameCount() < 2) {
      return;
    }

    frameIndex = 0;
    tick();
  };

  const init = () => {
    startAnimation();

    document.addEventListener("visibilitychange", startAnimation);
    window.addEventListener("pjax:send", stopAnimation);
    window.addEventListener("pjax:complete", startAnimation);
  };

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init, { once: true });
  } else {
    init();
  }
})();
