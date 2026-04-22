from __future__ import annotations

from typing import Any
from urllib.parse import urlparse
import xml.etree.ElementTree as ET

import requests


DEFAULT_TIMEOUT = 20
SNIPPET_LIMIT = 500
STATUS_DATA_KEY = "status_data"
COUNTER_DATA_KEY = "counter_data"


STATUS_PAYLOAD = """<DeviceInformationModel>
<GetValue><Controller><Information/><Settings><AdminSystemSettings><EFiling><eFilingEnabled/></EFiling><Copy/></AdminSystemSettings><WebDataRetentionPeriod/></Settings></Controller></GetValue>
<GetValue><MFP><DeviceState></DeviceState><ErrorState></ErrorState><Printer></Printer><Fax></Fax><ModelName></ModelName><System><PageMemory></PageMemory><MainMemory></MainMemory><HDD></HDD></System></MFP></GetValue>
<GetValue><FileStorages><FileStorage selected='1'><name>SaveAsFile</name></FileStorage><FileStorage selected='1'><name>FaxStorage</name></FileStorage></FileStorages></GetValue>
<GetValue><Network><Adapters><Wire/><Wireless/></Adapters><Protocols><TCP-IP><hostName></hostName></TCP-IP></Protocols></Network></GetValue>
<GetValue><DiagnosticMode><Category><Mode>08</Mode><MainCode><Code>8625</Code></MainCode><MainCode><Code>8870</Code></MainCode><MainCode><Code>5158</Code></MainCode><MainCode><Code>8876</Code></MainCode></Category></DiagnosticMode></GetValue>
<SetValue><FileStorages><FileStorage selected='1'><name>SaveAsFile</name></FileStorage><FileStorage selected='1'><name>FaxStorage</name></FileStorage></FileStorages></SetValue>
<SetValue><DiagnosticMode><Category><Mode>08</Mode><MainCode><Code>8625</Code></MainCode><MainCode><Code>8870</Code></MainCode><MainCode><Code>8876</Code></MainCode><MainCode><Code>5158</Code></MainCode></Category></DiagnosticMode></SetValue>
<Command><GetPhysicalSpaceInfo><commandNode>FileStorages</commandNode></GetPhysicalSpaceInfo></Command>
<Command><GetDiagnosticMode><commandNode>DiagnosticMode</commandNode></GetDiagnosticMode></Command>
</DeviceInformationModel>"""


COUNTER_PAYLOADS = [
    """<DeviceInformationModel>
<GetValue><DeviceService><DeviceCounters></DeviceCounters></DeviceService></GetValue>
</DeviceInformationModel>""",
    """<DeviceInformationModel>
<GetValue><DeviceService><DeviceCounters></DeviceCounters></DeviceService></GetValue>
<Command><GetDeviceCounters><commandNode>DeviceService/DeviceCounters</commandNode><Params><deviceCounterDetails contentType='XPath'></deviceCounterDetails></Params></GetDeviceCounters></Command>
</DeviceInformationModel>""",
]


def normalize_urls(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        raise ValueError(f"Invalid URL: {url}")
    return url, f"{parsed.scheme}://{parsed.netloc}"


def bootstrap_session(
    session: requests.Session,
    landing_url: str,
    origin: str,
    timeout: int,
) -> None:
    candidates = [landing_url]
    default_url = f"{origin}/?MAIN=TOPACCESS"
    if landing_url.rstrip("/") != default_url:
        candidates.append(default_url)
    seen: set[str] = set()
    last_error: Exception | None = None
    for candidate in candidates:
        if candidate in seen:
            continue
        seen.add(candidate)
        try:
            response = session.get(candidate, timeout=timeout)
            response.raise_for_status()
            if session.cookies.get("Session"):
                return
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue
    if last_error is not None:
        raise last_error
    raise RuntimeError("Unable to bootstrap Toshiba TopAccess session")


def compact_snippet(text: str, limit: int = SNIPPET_LIMIT) -> str:
    collapsed = " ".join(str(text or "").split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[:limit] + "..."


def build_response_meta(response: requests.Response, body: str, label: str) -> dict[str, Any]:
    return {
        "label": label,
        "status_code": response.status_code,
        "reason": response.reason,
        "final_url": response.url,
        "content_type": response.headers.get("Content-Type", ""),
        "body_length": len(body),
        "body_snippet": compact_snippet(body, 240),
    }


def post_contentwebserver(
    session: requests.Session,
    content_url: str,
    payload: str,
    csrf_token: str,
    timeout: int,
    label: str,
) -> tuple[str, dict[str, Any]]:
    response = session.post(
        content_url,
        data=payload.encode("utf-8"),
        headers={
            "Content-Type": "text/plain; charset=utf-8",
            "csrfpId": csrf_token,
        },
        timeout=timeout,
    )
    body = response.text
    meta = build_response_meta(response, body, label=label)
    response.raise_for_status()
    return body, meta


def post_contentwebserver_with_fallback(
    session: requests.Session,
    content_url: str,
    payloads: list[str],
    csrf_token: str,
    timeout: int,
    label: str,
) -> tuple[str, dict[str, Any]]:
    last_body = ""
    last_meta: dict[str, Any] | None = None
    last_error: Exception | None = None
    for index, payload in enumerate(payloads, 1):
        try:
            body, meta = post_contentwebserver(
                session=session,
                content_url=content_url,
                payload=payload,
                csrf_token=csrf_token,
                timeout=timeout,
                label=f"{label}_{index}",
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue
        if "MODULE_ERROR:" in body:
            last_body = body
            last_meta = meta
            continue
        return body, meta
    if last_meta is not None:
        raise RuntimeError(
            "All Toshiba counter payload attempts failed. "
            f"Last response: status={last_meta.get('status_code')} "
            f"content_type={last_meta.get('content_type')} "
            f"snippet={compact_snippet(last_body, 300)}"
        )
    if last_error is not None:
        raise last_error
    raise RuntimeError("All Toshiba counter payload attempts failed before any response was received.")


def extract_device_information_model(
    raw_text: str,
    source_label: str = "",
    response_meta: dict[str, Any] | None = None,
) -> str:
    start = raw_text.find("<DeviceInformationModel>")
    end = raw_text.rfind("</DeviceInformationModel>")
    if start != -1 and end != -1:
        end += len("</DeviceInformationModel>")
        return raw_text[start:end]

    details: list[str] = []
    if source_label:
        details.append(f"source={source_label}")
    if response_meta:
        details.extend(
            [
                f"status={response_meta.get('status_code')}",
                f"content_type={response_meta.get('content_type')}",
                f"url={response_meta.get('final_url')}",
            ]
        )
    if not str(raw_text or "").strip():
        details.append("response=empty")
    else:
        if "<html" in raw_text.lower():
            details.append("response=html_login_or_error_page")
        details.append(f"snippet={compact_snippet(raw_text)}")
    raise RuntimeError(
        "DeviceInformationModel root not found in Toshiba response. " + " | ".join(details)
    )


def parse_device_information_model(
    raw_text: str,
    source_label: str = "",
    response_meta: dict[str, Any] | None = None,
) -> ET.Element:
    xml_text = extract_device_information_model(
        raw_text,
        source_label=source_label,
        response_meta=response_meta,
    )
    try:
        return ET.fromstring(xml_text)
    except ET.ParseError as exc:
        raise RuntimeError(
            f"Failed to parse DeviceInformationModel XML for `{source_label or 'response'}`."
        ) from exc


def find_text(root: ET.Element, xpath: str) -> str | None:
    node = root.find(xpath)
    if node is None or node.text is None:
        return None
    text = node.text.strip()
    return text or None


def first_non_empty(*values: str | None) -> str | None:
    for value in values:
        if value:
            return value
    return None


def flatten_xml(root: ET.Element | None) -> dict[str, str]:
    if root is None:
        return {}

    output: dict[str, str] = {}

    def walk(node: ET.Element, path: str) -> None:
        children = list(node)
        text = (node.text or "").strip()
        if not children:
            if text:
                output[path] = text
            for attr_name, attr_value in node.attrib.items():
                output[f"{path}/@{attr_name}"] = attr_value
            return

        for attr_name, attr_value in node.attrib.items():
            output[f"{path}/@{attr_name}"] = attr_value

        counts: dict[str, int] = {}
        for child in children:
            counts[child.tag] = counts.get(child.tag, 0) + 1

        seen: dict[str, int] = {}
        for child in children:
            seen[child.tag] = seen.get(child.tag, 0) + 1
            child_path = f"{path}/{child.tag}"
            if counts[child.tag] > 1:
                child_path = f"{child_path}[{seen[child.tag]}]"
            walk(child, child_path)

    walk(root, root.tag)
    return output
