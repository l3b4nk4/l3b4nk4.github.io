var getRealPath = (pathname = window.location.pathname, desc = false) => {
  const names = pathname.split("/").filter((name) => {
    name = name.trim();
    return name.length > 0 && name !== "/" && name !== "index.html";
  });
  if (desc) {
    return names[0] || "/";
  } else {
    return names[names.length - 1] || "/";
  }
};

var getArticleScrollContainer = () =>
  document.querySelector(
    "body.mainsection-scroll-page #main > article.article",
  ) as HTMLElement | null;

var getScrollTop = (scrollContainer?: HTMLElement | null) => {
  if (scrollContainer) {
    return scrollContainer.scrollTop;
  }
  return document.documentElement.scrollTop || document.body.scrollTop;
};

var scrollIntoViewAndWait = (
  element: HTMLElement,
  scrollContainer?: HTMLElement | null,
) => {
  return new Promise<void>((resolve) => {
    const scrollTarget = scrollContainer || document;
    if ("onscrollend" in scrollTarget) {
      scrollTarget.addEventListener("scrollend", resolve as any, {
        once: true,
      });
      element.scrollIntoView({
        behavior: "smooth",
        block: "start",
        inline: "nearest",
      });
    } else {
      element.scrollIntoView({ block: "start", inline: "nearest" });
      resolve();
    }
  });
};

// anchor
_$$(
  ".article-entry h1>a.header-anchor, .article-entry h2>a.header-anchor, .article-entry h3>a.header-anchor, .article-entry h4>a.header-anchor, .article-entry h5>a.header-anchor, .article-entry h6>a.header-anchor",
).forEach((element) => {
  if (window.siteConfig.icon_font) {
    element.innerHTML = window.siteConfig.anchor_icon
      ? `&#x${window.siteConfig.anchor_icon};`
      : window.siteConfig.anchor_icon === false
        ? ""
        : "&#xe635;";
  } else {
    element.innerHTML = window.siteConfig.anchor_icon
      ? `&#x${window.siteConfig.anchor_icon};`
      : window.siteConfig.anchor_icon === false
        ? ""
        : "&#xf292;";
  }
});

// lightbox
(_$$(".article-entry img") as unknown as HTMLImageElement[]).forEach(
  (element) => {
    if (
      element.parentElement?.classList.contains("friend-icon") ||
      element.parentElement?.tagName === "A" ||
      element.classList.contains("no-lightbox")
    )
      return;
    const a = document.createElement("a");
    a.href ? (a.href = element.src) : a.setAttribute("href", element.src);
    a.dataset.pswpWidth = element.naturalWidth as any;
    a.dataset.pswpHeight = element.naturalHeight as any;
    a.target = "_blank";
    a.classList.add("article-gallery-item");
    element.parentNode?.insertBefore(a, element);
    element.parentNode?.removeChild(element);
    a.appendChild(element);
  },
);

// table wrap
_$$(".article-entry table").forEach((element) => {
  if (element.closest("div.highlight")) return;
  const wrapper = document.createElement("div");
  wrapper.classList.add("table-wrapper");
  element.parentNode?.insertBefore(wrapper, element);
  element.parentNode?.removeChild(element);
  wrapper.appendChild(element);
});

// Mobile nav
var isMobileNavAnim = false;
var closeMobileNav = () => {
  if (!document.body.classList.contains("mobile-nav-on"))
    return false;
  isMobileNavAnim = false;
  document.body.classList.remove("mobile-nav-on");
  _$("#mask").classList.add("hide");
  return true;
};

_$("#main-nav-toggle")
  ?.off("click")
  .on("click", () => {
    if (isMobileNavAnim) return;
    isMobileNavAnim = true;
    document.body.classList.toggle("mobile-nav-on");
    _$("#mask").classList.remove("hide");
    setTimeout(() => {
      isMobileNavAnim = false;
    }, 300);
  });

_$("#mask")
  ?.off("click")
  .on("click", () => {
    closeMobileNav();
  });

_$("#mobile-nav .mobile-nav-close")
  ?.off("click")
  .on("click", () => {
    closeMobileNav();
  });

_$$("#mobile-nav .mobile-toc-back").forEach((element) => {
  element.off("click").on("click", (event) => {
    event.preventDefault();
    closeMobileNav();
  });
});

_$$(".sidebar-toc-btn").forEach((element) => {
  element.off("click").on("click", function () {
    if (this.classList.contains("current")) return;
    _$$(".sidebar-toc-btn").forEach((element) =>
      element.classList.add("current"),
    );
    _$$(".sidebar-common-btn").forEach((element) =>
      element.classList.remove("current"),
    );
    _$$(".sidebar-toc-sidebar").forEach((element) =>
      element.classList.remove("hidden"),
    );
    _$$(".sidebar-common-sidebar").forEach((element) =>
      element.classList.add("hidden"),
    );
  });
});

_$$(".sidebar-common-btn").forEach((element) => {
  element.off("click").on("click", function () {
    if (this.classList.contains("current")) return;
    _$$(".sidebar-common-btn").forEach((element) =>
      element.classList.add("current"),
    );
    _$$(".sidebar-toc-btn").forEach((element) =>
      element.classList.remove("current"),
    );
    _$$(".sidebar-common-sidebar").forEach((element) =>
      element.classList.remove("hidden"),
    );
    _$$(".sidebar-toc-sidebar").forEach((element) =>
      element.classList.add("hidden"),
    );
  });
});

(() => {
  const rootRealPath = getRealPath(window.location.pathname);
  _$$(".sidebar-menu-link-wrap").forEach((link) => {
    let linkPath = link.querySelector("a")?.getAttribute("href");
    if (linkPath && getRealPath(linkPath) === rootRealPath) {
      link.classList.add("link-active");
    }
  });
})();

// lazyload
(_$$(".article-entry img") as unknown as HTMLImageElement[]).forEach(
  (element) => {
    if (element.classList.contains("lazyload")) return;
    element.classList.add("lazyload");
    element.setAttribute("data-src", element.src);
    element.setAttribute("data-sizes", "auto");
    element.removeAttribute("src");
  },
);

// to top
var sidebarTop = _$(".sidebar-top");
if (sidebarTop) {
  sidebarTop.style.transition = "opacity 1s";
  sidebarTop.off("click").on("click", () => {
    window.scrollTo({
      top: 0,
      behavior: "smooth",
    });
  });
  if (document.documentElement.scrollTop < 10) {
    sidebarTop.style.opacity = "0";
  }
}

var __sidebarTopScrollHandler;

if (__sidebarTopScrollHandler) {
  window.off("scroll", __sidebarTopScrollHandler);
}

__sidebarTopScrollHandler = () => {
  const sidebarTop = _$(".sidebar-top")!;
  if (document.documentElement.scrollTop < 10) {
    sidebarTop.style.opacity = "0";
  } else {
    sidebarTop.style.opacity = "1";
  }
};

window.on("scroll", __sidebarTopScrollHandler);

// toc
_$$("#mobile-nav #TableOfContents li").forEach((element) => {
  element.off("click").on("click", () => {
    closeMobileNav();
  });
});

_$$("#mobile-nav .sidebar-menu-link-dummy").forEach((element) => {
  element.off("click").on("click", () => {
    if (isMobileNavAnim || !document.body.classList.contains("mobile-nav-on"))
      return;
    setTimeout(() => {
      document.body.classList.remove("mobile-nav-on");
      _$("#mask").classList.add("hide");
    }, 200);
  });
});

function tocInit() {
  if (!_$("#sidebar")) return;
  const scrollContainer = getArticleScrollContainer();
  const navItems =
    getComputedStyle(_$("#sidebar")!).display === "block"
      ? _$$("#sidebar .sidebar-toc-wrapper li")
      : _$$("#mobile-nav .sidebar-toc-wrapper li");
  if (!navItems.length) return;

  let activeLock = null;
  let scrollDelta = 0;
  let lastScrollTop = getScrollTop(scrollContainer);

  const syncScrollDirection = () => {
    const scrollTop = getScrollTop(scrollContainer);
    scrollDelta = scrollTop - lastScrollTop;
    window.diffY = scrollDelta;
    lastScrollTop = scrollTop;
  };

  (scrollContainer || document).off("scroll", syncScrollDirection);
  (scrollContainer || document).on("scroll", syncScrollDirection);
  syncScrollDirection();

  const anchorScroll = (event, index) => {
    event.preventDefault();
    const target = document.getElementById(
      decodeURI(event.currentTarget.getAttribute("href")).slice(1),
    );
    activeLock = index;
    scrollIntoViewAndWait(target!, scrollContainer).then(() => {
      activateNavByIndex(index);
      activeLock = null;
    });
  };

  const sections = [...navItems].map((element, index) => {
    const link = element.querySelector("a");
    link!.off("click").on("click", (e) => anchorScroll(e, index));
    const anchor = document.getElementById(
      decodeURI(link.getAttribute("href")).slice(1),
    );
    if (!anchor) return null;
    const alink = anchor.querySelector("a");
    alink?.off("click").on("click", (e) => anchorScroll(e, index));
    return anchor;
  });

  const activateNavByIndex = (index) => {
    const target = navItems[index];

    if (!target || target.classList.contains("current")) return;

    _$$(".sidebar-toc-wrapper .current, .sidebar-toc-wrapper .active-parent").forEach((element) => {
      element.classList.remove("current", "active-parent");
    });

    sections.forEach((element) => {
      element?.classList.remove("active", "active-parent");
    });

    target.classList.add("current");
    sections[index]?.classList.add("active");

    let parent = target.parentNode as HTMLElement;

    while (!parent.matches(".sidebar-toc-sidebar")) {
      if (parent.matches("li")) {
        parent.classList.add("active-parent");
        const t = document.getElementById(
          decodeURI(parent.querySelector("a").getAttribute("href").slice(1)),
        );
        if (t) {
          t.classList.add("active-parent");
        }
      }
      parent = parent.parentNode as HTMLElement;
    }

    const hiddenToc = _$(".sidebar-toc-sidebar.hidden");
    const tocWrapper = _$(".sidebar-toc-wrapper") as HTMLElement | null;
    if (hiddenToc && tocWrapper) {
      tocWrapper.scrollTo({
        top: tocWrapper.scrollTop + target.offsetTop - tocWrapper.offsetHeight / 2,
        behavior: "smooth",
      });
    }
  };

  const findIndex = (entries) => {
    let index = 0;
    let entry = entries[index];

    if (entry.boundingClientRect.top > 0) {
      index = sections.indexOf(entry.target);
      return index === 0 ? 0 : index - 1;
    }
    for (; index < entries.length; index++) {
      if (entries[index].boundingClientRect.top <= 0) {
        entry = entries[index];
      } else {
        return sections.indexOf(entry.target);
      }
    }
    return sections.indexOf(entry.target);
  };

  const observer = new IntersectionObserver(
    (entries) => {
      const index = Math.max(0, findIndex(entries) + (scrollDelta > 0 ? 1 : 0));
      if (activeLock === null) {
        activateNavByIndex(index);
      }
    },
    {
      root: scrollContainer || null,
      rootMargin: "0px 0px -72% 0px",
      threshold: 0,
    },
  );

  sections.forEach((element) => {
    element && observer.observe(element);
  });

  activateNavByIndex(0);
}

tocInit();

_$(".sponsor-button")
  ?.off("click")
  .on("click", () => {
    _$(".sponsor-button")?.classList.toggle("active");
    _$(".sponsor-tip")?.classList.toggle("active");
    _$(".sponsor-qr")?.classList.toggle("active");
  });

var shareWeixinHandler: (e: any) => void;
if (shareWeixinHandler) {
  document.off("click", shareWeixinHandler);
}
shareWeixinHandler = (e) => {
  if (e.target.closest(".share-icon.icon-weixin")) return;
  const sw = _$("#share-weixin") as HTMLElement | null;
  if (sw && sw.classList.contains("active")) {
    sw.classList.remove("active");
    sw.addEventListener(
      "transitionend",
      function handler() {
        sw.style.display = "none";
        sw.removeEventListener("transitionend", handler);
      },
      { once: true },
    );
  }
};
document.on("click", shareWeixinHandler);

_$(".share-icon.icon-weixin")
  ?.off("click")
  .on("click", function (e) {
    const iconPosition = this.getBoundingClientRect();
    const shareWeixin = this.querySelector("#share-weixin");

    if (iconPosition.x - 148 < 0) {
      shareWeixin.style.left = `-${iconPosition.x - 10}px`;
    } else if (iconPosition.x + 172 > window.innerWidth) {
      shareWeixin.style.left = `-${310 - window.innerWidth + iconPosition.x}px`;
    } else {
      shareWeixin.style.left = "-138px";
    }
    if (e.target === this) {
      const el = shareWeixin as HTMLElement;
      if (!el) return;
      if (!el.classList.contains("active")) {
        el.style.display = "block";
        requestAnimationFrame(() => {
          el.classList.add("active");
        });
      } else {
        el.classList.remove("active");
        const onEnd = (ev: TransitionEvent) => {
          if (ev.propertyName === "opacity") {
            el.style.display = "none";
            el.removeEventListener("transitionend", onEnd as any);
          }
        };
        el.addEventListener("transitionend", onEnd as any);
      }
    }
    // if contains img return
    if (_$(".share-weixin-canvas").children.length) {
      return;
    }
    const { cover, description, title, author } = window.REIMU_POST;
    (_$("#share-weixin-banner") as HTMLImageElement).src = cover;
    _$("#share-weixin-title").innerText = title;
    _$("#share-weixin-desc").innerText = description.replace(/\s/g, " ");
    _$("#share-weixin-author").innerText = "By: " + author;
    QRCode.toDataURL(window.REIMU_POST.url, function (error, dataUrl) {
      if (error) {
        console.error(error);
        return;
      }
      (_$("#share-weixin-qr") as HTMLImageElement).src = dataUrl;
      snapdom
        .toPng(_$(".share-weixin-dom"))
        .then((img) => {
          _$(".share-weixin-canvas").appendChild(img);
        })
        .catch(() => {
          // we assume that the error is caused by the browser's security policy
          // so we will remove the banner and try again
          _$("#share-weixin-banner").remove();
          snapdom
            .toPng(_$(".share-weixin-dom"))
            .then((img) => {
              _$(".share-weixin-canvas").appendChild(img);
            })
            .catch(() => {
              console.error("Failed to generate weixin share image.");
            });
        });
    });
  });

const imgElement = _$("#header > img") as HTMLImageElement;
if (imgElement.src || imgElement.style.background) {
  window.bannerElement = imgElement;
} else {
  window.bannerElement = _$("#header > picture img") as HTMLImageElement;
}

window.generateSchemeHandler?.();
