"""HTML form parser with JavaScript event handling.

Extracts forms from crawled HTML, analyzes event handlers (onsubmit, oninput, etc.),
and generates form fuzzing tasks including CSRF token extraction.
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from basilisk.models import Finding

logger = logging.getLogger(__name__)

# Common JavaScript event handler patterns
JS_EVENTS = (
    "onabort",
    "onblur",
    "oncanplay",
    "oncanplaythrough",
    "onchange",
    "onclick",
    "oncontextmenu",
    "oncuechange",
    "ondblclick",
    "ondrag",
    "ondragend",
    "ondragenter",
    "ondragleave",
    "ondragover",
    "ondrop",
    "onerror",
    "onfocus",
    "oninput",
    "oninvalid",
    "onkeydown",
    "onkeypress",
    "onkeyup",
    "onload",
    "onloadeddata",
    "onloadedmetadata",
    "onmousedown",
    "onmousemove",
    "onmouseout",
    "onmouseover",
    "onmouseup",
    "onmousewheel",
    "onpause",
    "onplay",
    "onplaying",
    "onprogress",
    "onratechange",
    "onreset",
    "onresize",
    "onscroll",
    "onseeked",
    "onseeking",
    "onselect",
    "onsubmit",
    "ontimeupdate",
    "ontoggle",
    "onunload",
    "onvolumechange",
    "onwaiting",
)

JS_EVENT_RE = re.compile(
    r"\b(" + "|".join(re.escape(e) for e in JS_EVENTS) + r")\s*=\s*(?:\"([^\"]*)\"|'([^']*)')",
    re.IGNORECASE,
)


@dataclass
class FormField:
    """Represents a form input field."""

    name: str
    type: str = "text"
    value: str = ""
    required: bool = False
    readonly: bool = False
    autocomplete: str = ""
    placeholder: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "type": self.type,
            "value": self.value,
            "required": self.required,
            "readonly": self.readonly,
            "autocomplete": self.autocomplete,
            "placeholder": self.placeholder,
        }


@dataclass
class FormResult:
    """Result of parsing an HTML form."""

    action: str
    method: str
    enctype: str = "application/x-www-form-urlencoded"
    fields: list[FormField] = field(default_factory=list)
    inputs: list[Dict[str, Any]] = field(default_factory=list)
    javascript_events: list[Dict[str, str]] = field(default_factory=list)
    csrf_token_name: str = ""
    csrf_token_value: str = ""
    form_id: str = ""

    def to_dict(self) -> dict:
        return {
            "action": self.action,
            "method": self.method,
            "enctype": self.enctype,
            "fields": [f.to_dict() for f in self.fields],
            "inputs": self.inputs,
            "javascript_events": self.javascript_events,
            "csrf_token_name": self.csrf_token_name,
            "csrf_token_value": self.csrf_token_value,
            "form_id": self.form_id,
        }


def extract_value(attr: str, default: str = "") -> str:
    """Extract the value attribute from an HTML attribute string."""
    if not attr:
        return default
    m = re.search(r'value="([^"]*)"', attr)
    if m:
        return m.group(1)
    return default


def extract_bool(attr: str, default: bool = False) -> bool:
    """Extract a boolean attribute presence."""
    return attr is not None and attr.lower() != "false"


def parse_javascript_events(html: str, form_start: int) -> list[Dict[str, str]]:
    """Parse JavaScript event handlers from HTML surrounding a form."""
    events: list[Dict[str, str]] = []
    snippet = html[form_start : form_start + 2000]
    for match in JS_EVENT_RE.finditer(snippet):
        event_name = match.group(1).lower()
        # group(2) or group(3) holds the handler code depending on quote type
        handler_code = match.group(2) if match.group(2) is not None else match.group(3)
        events.append({event_name: handler_code})
    return events


def find_csrf_token(form_html: str, field_name: str = "csrf_token") -> tuple[str, str]:
    """Attempt to extract a CSRF token from form HTML.

    Looks for hidden input with the given name, or meta tag, or JS-derived token.
    Returns (token_name, token_value).
    """
    # Hidden input
    m = re.search(
        rf'<input[^>]*name="{re.escape(field_name)}"[^>]*value="([^"]*)"',
        form_html,
        re.IGNORECASE,
    )
    if m:
        return field_name, m.group(1)

    # Meta tag
    m = re.search(
        rf'<meta[^>]*content="([^"]*)"[^>]*name="[^"]*{re.escape(field_name)}"',
        form_html,
        re.IGNORECASE,
    )
    if m:
        return field_name, ""

    # JS-derived: look for token in onsubmit or inline script
    m = re.search(rf"(?:var|let|const)\s+{field_name}\s*=\s*['\"]([^'\"]+)['\"]", form_html, re.IGNORECASE)
    if m:
        return field_name, m.group(1)

    return "", ""


def parse_form(form_html: str, base_url: str) -> FormResult:
    """Parse an HTML form from raw HTML string.

    Returns a FormResult with fields, method, action, JS events, and CSRF token info.
    """
    result = FormResult(action=base_url, method="GET")

    # Extract action
    m = re.search(r'<form[^>]*action="([^"]*)"', form_html, re.IGNORECASE)
    if m:
        result.action = m.group(1)
    else:
        m = re.search(r'<form[^>]*>', form_html, re.IGNORECASE)
        if m:
            result.action = base_url

    # Extract method
    m = re.search(r'<form[^>]*method="([^"]*)"', form_html, re.IGNORECASE)
    if m:
        result.method = m.group(1).upper()
    else:
        result.method = "GET"

    # Extract enctype
    m = re.search(r'<form[^>]*enctype="([^"]*)"', form_html, re.IGNORECASE)
    if m:
        result.enctype = m.group(1)

    # Extract input fields
    field_matches = re.finditer(r'<input[^>]+>', form_html, re.IGNORECASE)
    for match in field_matches:
        field_html = match.group(0)
        fname = ""
        ftype = "text"
        fvalue = ""
        frequired = False
        freadonly = False
        fauto = ""
        fplaceholder = ""

        # name
        nm = re.search(r'name="([^"]*)"', field_html, re.IGNORECASE)
        if nm:
            fname = nm.group(1)

        # type
        tm = re.search(r'type="([^"]*)"', field_html, re.IGNORECASE)
        if tm:
            ftype = tm.group(1).lower()

        # value
        fvalue = extract_value(field_html)
        if fvalue is not None:
            pass  # fvalue already set by extract_value

        # required
        rm = re.search(r'required="[^"]*"', field_html, re.IGNORECASE)
        if rm:
            frequired = True

        # readonly
        rokm = re.search(r'readonly="[^"]*"', field_html, re.IGNORECASE)
        if rokm:
            freadonly = True

        # autocomplete
        am = re.search(r'autocomplete="([^"]*)"', field_html, re.IGNORECASE)
        if am:
            fauto = am.group(1)

        # placeholder
        pm = re.search(r'placeholder="([^"]*)"', field_html, re.IGNORECASE)
        if pm:
            fplaceholder = pm.group(1)

        result.fields.append(
            FormField(
                name=fname,
                type=ftype,
                value=fvalue,
                required=frequired,
                readonly=freadonly,
                autocomplete=fauto,
                placeholder=fplaceholder,
            )
        )

    # Extract textarea and select elements
    input_matches = re.finditer(r'<(textarea|select)[^>]+>', form_html, re.IGNORECASE)
    for match in input_matches:
        ihtml = match.group(0)
        iname = ""
        itype = match.group(1).lower()

        nm = re.search(r'name="([^"]*)"', ihtml, re.IGNORECASE)
        if nm:
            iname = nm.group(1)

        # textarea content
        content_m = re.search(r">([^<]*)<", ihtml)
        cvalue = content_m.group(1) if content_m else ""

        result.fields.append(
            FormField(
                name=iname,
                type=itype,
                value=cvalue,
                required=False,
                readonly=False,
            )
        )

    # Find the form ID
    id_m = re.search(r'id="([^"]*)"', form_html, re.IGNORECASE)
    if id_m:
        result.form_id = id_m.group(1)

    # Parse JavaScript events
    # Find the form start position
    form_start = form_html.find("<form")
    result.javascript_events = parse_javascript_events(form_html, form_start)

    # Extract CSRF token
    result.csrf_token_name, result.csrf_token_value = find_csrf_token(form_html, "csrf_token")

    # Also check for alternative names
    for alt_name in ["token", "authenticity_token", "session_token"]:
        tn, tv = find_csrf_token(form_html, alt_name)
        if tv and not result.csrf_token_value:
            result.csrf_token_name = tn
            result.csrf_token_value = tv

    return result