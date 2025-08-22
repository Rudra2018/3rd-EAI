# scanner/adapter.py
import inspect
import logging
from typing import Any, Dict, Iterable, List, Optional, Union

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class ScannerAdapter:
    _CANDIDATES = ["scan_endpoint", "scan", "scan_url", "request", "execute", "audit", "test", "run", "call"]

    def __init__(
        self,
        scanner: Any,
        http_fallback: bool = True,
        timeout: float = 12.0,
        pool_maxsize: int = 200,     # ↑ bigger pool
        verify_ssl: bool = True,
        default_headers: Optional[Dict[str, str]] = None,
        retries: Optional[Retry] = None,
        user_agent: str = "Rudra-Scanner/1.0",
    ):
        self.scanner = scanner
        self.http_fallback = http_fallback
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self._native_method_name = self._detect_native_method()
        self.log = logging.getLogger(__name__)

        # Pooled session (block instead of discarding when pool full)
        self.session = requests.Session()
        retry_cfg = retries or Retry(
            total=2, backoff_factor=0.2, status_forcelist=[502, 503, 504],
            allowed_methods=False, raise_on_status=False, raise_on_redirect=False
        )
        adapter = HTTPAdapter(
            pool_connections=pool_maxsize,
            pool_maxsize=pool_maxsize,
            max_retries=retry_cfg,
            pool_block=True,                  # ← key: wait for a slot instead of “discarding connection”
        )
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

        self.default_headers = {"User-Agent": user_agent, "Connection": "keep-alive"}
        if default_headers:
            self.default_headers.update(default_headers)

        if self._native_method_name:
            self.log.info(f"ScannerAdapter: using native method '{self._native_method_name}'")
        else:
            self.log.info("ScannerAdapter: no native scan method found, using HTTP probe fallback")

    def call(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
             data: Optional[Union[Dict, str, bytes]] = None, params: Optional[Dict[str, str]] = None) -> List[Dict]:
        headers = headers or {}
        if self._native_method_name:
            try:
                native_fn = getattr(self.scanner, self._native_method_name)
                result = self._invoke_native(native_fn, url, method, headers, data, params)
                return self._normalize(result)
            except Exception as e:
                self.log.debug(f"Native scan method failed: {e}", exc_info=True)

        if self.http_fallback:
            try:
                return self._http_probe(url, method, headers=headers, data=data, params=params)
            except Exception as e:
                self.log.debug(f"HTTP probe failed: {e}", exc_info=True)

        return []

    def scan_endpoint(self, url: str, method: str = "GET", headers=None, data=None, params=None) -> List[Dict]:
        return self.call(url, method=method, headers=headers, data=data, params=params)

    def _detect_native_method(self) -> Optional[str]:
        for name in self._CANDIDATES:
            fn = getattr(self.scanner, name, None)
            if callable(fn): return name
        for name, fn in inspect.getmembers(self.scanner, predicate=callable):
            if "scan" in name.lower(): return name
        return None

    def _invoke_native(self, fn: Any, url: str, method: str, headers: Dict[str, str],
                       data: Optional[Union[Dict, str, bytes]], params: Optional[Dict[str, str]]) -> Any:
        try:
            sig = inspect.signature(fn)
        except Exception:
            sig = None

        if sig:
            names = list(sig.parameters.keys())
            kwargs, args = {}, []

            if "url" in names: kwargs["url"] = url
            else: args.append(url)
            if "method" in names: kwargs["method"] = method
            else: args.append(method)
            if "headers" in names: kwargs["headers"] = headers
            if "data" in names: kwargs["data"] = data
            if "params" in names: kwargs["params"] = params
            if any(n in names for n in ("session", "http", "requests_session")):
                if "session" in names: kwargs["session"] = self.session
                elif "http" in names: kwargs["http"] = self.session
                else: kwargs["requests_session"] = self.session
            try:
                return fn(*args, **kwargs)
            except TypeError:
                pass

        for attempt in [(url, method, headers, data), (url, method), (url,)]:
            try:
                return fn(*attempt)
            except TypeError:
                continue
        return fn(url)

    def _normalize(self, result: Any) -> List[Dict]:
        if not result: return []
        if isinstance(result, dict): return [result]
        out = []
        if isinstance(result, (list, tuple)):
            for v in result:
                if v is None: continue
                if hasattr(v, "to_dict"):
                    try: out.append(v.to_dict()); continue
                    except Exception: pass
                if isinstance(v, dict): out.append(v)
        return out

    def _http_probe(self, url: str, method: str, headers=None, data=None, params=None) -> List[Dict]:
        # Always close response so connection is returned to pool
        hdrs = dict(self.default_headers)
        if headers: hdrs.update(headers)

        json_payload, data_payload = None, None
        if isinstance(data, dict) and "raw_body" not in data:
            json_payload = data
        elif isinstance(data, (str, bytes)):
            data_payload = data
        elif isinstance(data, dict) and "raw_body" in data:
            data_payload = data.get("raw_body")

        try:
            with self.session.request(
                method=str(method or "GET").upper(),
                url=url, headers=hdrs,
                json=json_payload, data=data_payload, params=params,
                timeout=self.timeout, allow_redirects=False, verify=self.verify_ssl,
                stream=False,  # ensure Requests reads/knows full body handling
            ) as resp:
                # We don't need the body; explicitly close anyway (context manager does, too)
                resp.close()
        except Exception:
            pass
        return []

    def close(self):
        try: self.session.close()
        except Exception: pass

    def __del__(self):
        try: self.close()
        except Exception: pass

