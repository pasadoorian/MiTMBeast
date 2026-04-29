"""Per-mode proxy lifecycle modules.

One module per ``mitm.sh`` proxy mode:

* :mod:`mitmbeast.core.proxy.sslsplit`  — SSL splitting + PCAP capture
* :mod:`mitmbeast.core.proxy.certmitm`  — TLS validation testing  (P2.11c)
* :mod:`mitmbeast.core.proxy.sslstrip`  — TLS downgrade testing   (P2.11b)
* :mod:`mitmbeast.core.proxy.intercept` — mitmproxy + fake firmware (P2.11d)
* :mod:`mitmbeast.core.proxy.mitmproxy_mode` — direct mitmproxy   (P2.10)

Each module exports a small surface — typically ``start(cfg, *)``
returning a :class:`ProxySession` (or similar) and ``stop(session)``.
:mod:`mitmbeast.core.router` dispatches based on ``cfg.PROXY_MODE``.
"""
