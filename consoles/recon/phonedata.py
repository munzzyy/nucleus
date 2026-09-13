"""Offline phone-number intelligence for the Recon console.

Every keyless phone API worth having now demands a key (numverify, veriphone,
abstract all 401 without one), so the way to make a keyless phone scan actually
show data is to parse the number properly ourselves. This module does that with
pure stdlib and static tables: it turns a raw string into a country (with flag),
clean E.164 / national / international formats, a line-type read (toll-free /
premium / geographic / ...), and for North American numbers the state, time
zone, and the current local time at that number.

No network, no key, no side effects. `analyze()` is the entry point;
`lookups.phone_scan` calls it and layers the optional keyed carrier lookups on
top. The US state still comes from `lookups.nanp_region` (passed in) so this
module never imports lookups back -- no cycle.
"""

from __future__ import annotations

import re
from datetime import datetime
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


def _flag(iso2: str) -> str:
    """Regional-indicator flag emoji from a 2-letter ISO country code, computed
    rather than tabled so there's one less column to get wrong."""
    iso2 = (iso2 or "").upper()
    if len(iso2) != 2 or not iso2.isalpha():
        return ""
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in iso2)


# Non-NANP country calling codes -> (country name, ISO2). +1 (NANP) is handled
# separately below via area code. Longest-prefix match wins (codes are 1-4
# digits; nothing but NANP starts with 1, nothing but Russia/KZ starts with 7).
_CC: dict[str, tuple[str, str]] = {
    "7": ("Russia", "RU"), "20": ("Egypt", "EG"), "27": ("South Africa", "ZA"),
    "30": ("Greece", "GR"), "31": ("Netherlands", "NL"), "32": ("Belgium", "BE"),
    "33": ("France", "FR"), "34": ("Spain", "ES"), "36": ("Hungary", "HU"),
    "39": ("Italy", "IT"), "40": ("Romania", "RO"), "41": ("Switzerland", "CH"),
    "43": ("Austria", "AT"), "44": ("United Kingdom", "GB"), "45": ("Denmark", "DK"),
    "46": ("Sweden", "SE"), "47": ("Norway", "NO"), "48": ("Poland", "PL"),
    "49": ("Germany", "DE"), "51": ("Peru", "PE"), "52": ("Mexico", "MX"),
    "53": ("Cuba", "CU"), "54": ("Argentina", "AR"), "55": ("Brazil", "BR"),
    "56": ("Chile", "CL"), "57": ("Colombia", "CO"), "58": ("Venezuela", "VE"),
    "60": ("Malaysia", "MY"), "61": ("Australia", "AU"), "62": ("Indonesia", "ID"),
    "63": ("Philippines", "PH"), "64": ("New Zealand", "NZ"), "65": ("Singapore", "SG"),
    "66": ("Thailand", "TH"), "81": ("Japan", "JP"), "82": ("South Korea", "KR"),
    "84": ("Vietnam", "VN"), "86": ("China", "CN"), "90": ("Turkey", "TR"),
    "91": ("India", "IN"), "92": ("Pakistan", "PK"), "93": ("Afghanistan", "AF"),
    "94": ("Sri Lanka", "LK"), "95": ("Myanmar", "MM"), "98": ("Iran", "IR"),
    "211": ("South Sudan", "SS"), "212": ("Morocco", "MA"), "213": ("Algeria", "DZ"),
    "216": ("Tunisia", "TN"), "218": ("Libya", "LY"), "220": ("Gambia", "GM"),
    "221": ("Senegal", "SN"), "222": ("Mauritania", "MR"), "223": ("Mali", "ML"),
    "224": ("Guinea", "GN"), "225": ("Ivory Coast", "CI"), "226": ("Burkina Faso", "BF"),
    "227": ("Niger", "NE"), "228": ("Togo", "TG"), "229": ("Benin", "BJ"),
    "230": ("Mauritius", "MU"), "231": ("Liberia", "LR"), "232": ("Sierra Leone", "SL"),
    "233": ("Ghana", "GH"), "234": ("Nigeria", "NG"), "235": ("Chad", "TD"),
    "236": ("Central African Republic", "CF"), "237": ("Cameroon", "CM"),
    "238": ("Cape Verde", "CV"), "239": ("Sao Tome and Principe", "ST"),
    "240": ("Equatorial Guinea", "GQ"), "241": ("Gabon", "GA"), "242": ("Congo", "CG"),
    "243": ("DR Congo", "CD"), "244": ("Angola", "AO"), "245": ("Guinea-Bissau", "GW"),
    "248": ("Seychelles", "SC"), "249": ("Sudan", "SD"), "250": ("Rwanda", "RW"),
    "251": ("Ethiopia", "ET"), "252": ("Somalia", "SO"), "253": ("Djibouti", "DJ"),
    "254": ("Kenya", "KE"), "255": ("Tanzania", "TZ"), "256": ("Uganda", "UG"),
    "257": ("Burundi", "BI"), "258": ("Mozambique", "MZ"), "260": ("Zambia", "ZM"),
    "261": ("Madagascar", "MG"), "263": ("Zimbabwe", "ZW"), "264": ("Namibia", "NA"),
    "265": ("Malawi", "MW"), "266": ("Lesotho", "LS"), "267": ("Botswana", "BW"),
    "268": ("Eswatini", "SZ"), "269": ("Comoros", "KM"), "290": ("Saint Helena", "SH"),
    "291": ("Eritrea", "ER"), "297": ("Aruba", "AW"), "298": ("Faroe Islands", "FO"),
    "299": ("Greenland", "GL"), "350": ("Gibraltar", "GI"), "351": ("Portugal", "PT"),
    "352": ("Luxembourg", "LU"), "353": ("Ireland", "IE"), "354": ("Iceland", "IS"),
    "355": ("Albania", "AL"), "356": ("Malta", "MT"), "357": ("Cyprus", "CY"),
    "358": ("Finland", "FI"), "359": ("Bulgaria", "BG"), "370": ("Lithuania", "LT"),
    "371": ("Latvia", "LV"), "372": ("Estonia", "EE"), "373": ("Moldova", "MD"),
    "374": ("Armenia", "AM"), "375": ("Belarus", "BY"), "376": ("Andorra", "AD"),
    "377": ("Monaco", "MC"), "378": ("San Marino", "SM"), "380": ("Ukraine", "UA"),
    "381": ("Serbia", "RS"), "382": ("Montenegro", "ME"), "383": ("Kosovo", "XK"),
    "385": ("Croatia", "HR"), "386": ("Slovenia", "SI"), "387": ("Bosnia and Herzegovina", "BA"),
    "389": ("North Macedonia", "MK"), "420": ("Czechia", "CZ"), "421": ("Slovakia", "SK"),
    "423": ("Liechtenstein", "LI"), "500": ("Falkland Islands", "FK"), "501": ("Belize", "BZ"),
    "502": ("Guatemala", "GT"), "503": ("El Salvador", "SV"), "504": ("Honduras", "HN"),
    "505": ("Nicaragua", "NI"), "506": ("Costa Rica", "CR"), "507": ("Panama", "PA"),
    "508": ("Saint Pierre and Miquelon", "PM"), "509": ("Haiti", "HT"),
    "590": ("Guadeloupe", "GP"), "591": ("Bolivia", "BO"), "592": ("Guyana", "GY"),
    "593": ("Ecuador", "EC"), "594": ("French Guiana", "GF"), "595": ("Paraguay", "PY"),
    "596": ("Martinique", "MQ"), "597": ("Suriname", "SR"), "598": ("Uruguay", "UY"),
    "599": ("Curacao", "CW"), "670": ("Timor-Leste", "TL"), "672": ("Norfolk Island", "NF"),
    "673": ("Brunei", "BN"), "674": ("Nauru", "NR"), "675": ("Papua New Guinea", "PG"),
    "676": ("Tonga", "TO"), "677": ("Solomon Islands", "SB"), "678": ("Vanuatu", "VU"),
    "679": ("Fiji", "FJ"), "680": ("Palau", "PW"), "681": ("Wallis and Futuna", "WF"),
    "682": ("Cook Islands", "CK"), "683": ("Niue", "NU"), "685": ("Samoa", "WS"),
    "686": ("Kiribati", "KI"), "687": ("New Caledonia", "NC"), "688": ("Tuvalu", "TV"),
    "689": ("French Polynesia", "PF"), "690": ("Tokelau", "TK"), "691": ("Micronesia", "FM"),
    "692": ("Marshall Islands", "MH"), "850": ("North Korea", "KP"), "852": ("Hong Kong", "HK"),
    "853": ("Macau", "MO"), "855": ("Cambodia", "KH"), "856": ("Laos", "LA"),
    "880": ("Bangladesh", "BD"), "886": ("Taiwan", "TW"), "960": ("Maldives", "MV"),
    "961": ("Lebanon", "LB"), "962": ("Jordan", "JO"), "963": ("Syria", "SY"),
    "964": ("Iraq", "IQ"), "965": ("Kuwait", "KW"), "966": ("Saudi Arabia", "SA"),
    "967": ("Yemen", "YE"), "968": ("Oman", "OM"), "970": ("Palestine", "PS"),
    "971": ("United Arab Emirates", "AE"), "972": ("Israel", "IL"), "973": ("Bahrain", "BH"),
    "974": ("Qatar", "QA"), "975": ("Bhutan", "BT"), "976": ("Mongolia", "MN"),
    "977": ("Nepal", "NP"), "992": ("Tajikistan", "TJ"), "993": ("Turkmenistan", "TM"),
    "994": ("Azerbaijan", "AZ"), "995": ("Georgia", "GE"), "996": ("Kyrgyzstan", "KG"),
    "998": ("Uzbekistan", "UZ"),
}

# +1 NANP: Caribbean and other non-US/Canada members keyed by area code, so a
# +1 number resolves to the right country instead of a blanket "US/Canada".
_NANP_COUNTRY: dict[str, tuple[str, str]] = {
    "242": ("Bahamas", "BS"), "246": ("Barbados", "BB"), "264": ("Anguilla", "AI"),
    "268": ("Antigua and Barbuda", "AG"), "284": ("British Virgin Islands", "VG"),
    "340": ("US Virgin Islands", "VI"), "345": ("Cayman Islands", "KY"),
    "441": ("Bermuda", "BM"), "473": ("Grenada", "GD"), "649": ("Turks and Caicos", "TC"),
    "664": ("Montserrat", "MS"), "670": ("Northern Mariana Islands", "MP"),
    "671": ("Guam", "GU"), "684": ("American Samoa", "AS"), "721": ("Sint Maarten", "SX"),
    "758": ("Saint Lucia", "LC"), "767": ("Dominica", "DM"), "784": ("St Vincent", "VC"),
    "787": ("Puerto Rico", "PR"), "809": ("Dominican Republic", "DO"),
    "829": ("Dominican Republic", "DO"), "849": ("Dominican Republic", "DO"),
    "868": ("Trinidad and Tobago", "TT"), "869": ("Saint Kitts and Nevis", "KN"),
    "876": ("Jamaica", "JM"), "939": ("Puerto Rico", "PR"),
}

# Canadian area codes -> so +1 resolves Canada, not the US-state table.
_CANADA_NPA = {
    "204", "226", "236", "249", "250", "289", "306", "343", "354", "365", "367",
    "368", "382", "403", "416", "418", "428", "431", "437", "438", "450", "468",
    "474", "506", "514", "519", "537", "548", "579", "581", "584", "587", "600",
    "604", "613", "639", "647", "672", "683", "705", "709", "742", "753", "778",
    "780", "782", "807", "819", "825", "867", "873", "879", "902", "905",
}

# US-state -> dominant IANA time zone. Split states carry a caveat flag below.
_STATE_ZONE = {
    "Alabama": "America/Chicago", "Alaska": "America/Anchorage", "Arizona": "America/Phoenix",
    "Arkansas": "America/Chicago", "California": "America/Los_Angeles", "Colorado": "America/Denver",
    "Connecticut": "America/New_York", "Delaware": "America/New_York",
    "District of Columbia": "America/New_York", "Florida": "America/New_York",
    "Georgia": "America/New_York", "Hawaii": "Pacific/Honolulu", "Idaho": "America/Boise",
    "Illinois": "America/Chicago", "Indiana": "America/Indiana/Indianapolis", "Iowa": "America/Chicago",
    "Kansas": "America/Chicago", "Kentucky": "America/New_York", "Louisiana": "America/Chicago",
    "Maine": "America/New_York", "Maryland": "America/New_York", "Massachusetts": "America/New_York",
    "Michigan": "America/Detroit", "Minnesota": "America/Chicago", "Mississippi": "America/Chicago",
    "Missouri": "America/Chicago", "Montana": "America/Denver", "Nebraska": "America/Chicago",
    "Nevada": "America/Los_Angeles", "New Hampshire": "America/New_York", "New Jersey": "America/New_York",
    "New Mexico": "America/Denver", "New York": "America/New_York", "North Carolina": "America/New_York",
    "North Dakota": "America/Chicago", "Ohio": "America/New_York", "Oklahoma": "America/Chicago",
    "Oregon": "America/Los_Angeles", "Pennsylvania": "America/New_York", "Rhode Island": "America/New_York",
    "South Carolina": "America/New_York", "South Dakota": "America/Chicago", "Tennessee": "America/Chicago",
    "Texas": "America/Chicago", "Utah": "America/Denver", "Vermont": "America/New_York",
    "Virginia": "America/New_York", "Washington": "America/Los_Angeles", "West Virginia": "America/New_York",
    "Wisconsin": "America/Chicago", "Wyoming": "America/Denver",
}

# States that span more than one US time zone -> the local time we show is the
# dominant zone and gets flagged approximate, never presented as exact.
_SPLIT_TZ_STATES = {
    "Florida", "Michigan", "Indiana", "Kentucky", "Tennessee", "Texas", "Kansas",
    "Nebraska", "North Dakota", "South Dakota", "Oregon", "Idaho",
}

# Area codes clearly in a non-dominant zone for their state -> exact override.
_NPA_ZONE_OVERRIDE = {
    "915": "America/Denver",   # El Paso, TX (Mountain)
    "806": "America/Chicago",  # Texas panhandle stays Central (dominant already)
}

_TOLL_FREE = {"800", "833", "844", "855", "866", "877", "888"}
_PERSONAL = {"500", "521", "522", "533", "544", "566", "577", "588", "589"}

# Countries whose national numbers keep the leading 0 (it is part of the
# number, not a trunk prefix to strip). Italy is the classic case.
_KEEPS_LEADING_ZERO = {"39"}

# +7 is shared by Russia and Kazakhstan. They are separable by the first digit
# of the national number: KZ uses 6 and 7, RU uses 3/4/5/8/9.
_PLUS7_KZ_FIRST_DIGITS = {"6", "7"}


def _digits(s: str) -> str:
    return re.sub(r"\D", "", s or "")


def _split_e164(digits: str, had_plus: bool) -> tuple[str | None, str, str]:
    """(calling_code, national_number, iso2) best-effort. NANP is code '1'."""
    d = digits
    # A leading + or a leading NANP 1 with 11 digits both mean an explicit code.
    if had_plus or (len(d) == 11 and d.startswith("1")):
        if d.startswith("1") and (len(d) == 11 or had_plus):
            return "1", d[1:], ""
        for length in (4, 3, 2, 1):
            code = d[:length]
            if code == "1":
                return "1", d[1:], ""
            if code in _CC:
                return code, d[length:], _CC[code][1]
        return None, d, ""
    # No plus and not an 11-digit NANP: a bare 10-digit run is NANP only if it
    # is structurally possible as one. Area code and exchange both have to
    # start 2-9, so a foreign domestic number written with a leading trunk 0
    # (or a 1) is no longer silently attributed to the United States.
    if len(d) == 10 and d[0] in "23456789" and d[3] in "23456789":
        return "1", d, ""
    return None, d, ""


def _nanp_format(national: str) -> tuple[str, str]:
    """(national_pretty, international_pretty) for a 10-digit NANP number."""
    if len(national) != 10:
        return national, "+1 " + national
    npa, nxx, xxxx = national[:3], national[3:6], national[6:]
    return f"({npa}) {nxx}-{xxxx}", f"+1 {npa}-{nxx}-{xxxx}"


def _intl_format(code: str, national: str) -> str:
    # Loose grouping: keep the national number in 2-3 digit chunks after the code.
    groups = []
    rest = national
    while rest:
        take = 3 if len(rest) % 3 == 0 or len(rest) > 4 else len(rest)
        groups.append(rest[:take])
        rest = rest[take:]
    return f"+{code} " + " ".join(groups) if groups else f"+{code}"


def _nanp_line_type(npa: str, nxx: str) -> tuple[str, str | None]:
    if npa in _TOLL_FREE:
        return "Toll-free", "caller pays nothing; reaches a business, not a location"
    if npa == "900":
        return "Premium rate", "caller is charged a premium; often paid services"
    if npa in _PERSONAL:
        return "Personal / follow-me", "a non-geographic personal number"
    if nxx == "555":
        return "Directory / fictional", "555 exchange, often a placeholder or directory number"
    return "Geographic", "landline or mobile -- North American numbering can't tell them apart offline (number portability)"


def _local_time(zone: str) -> str | None:
    try:
        return datetime.now(ZoneInfo(zone)).strftime("%Y-%m-%d %H:%M %Z")
    except (ZoneInfoNotFoundError, ValueError, OSError):
        return None


def analyze(raw: str, area_code: str | None, us_region: str | None) -> dict:
    """Rich offline read of a phone number. `area_code`/`us_region` come from
    lookups (the existing NANP tables) so this stays import-cycle-free."""
    had_plus = "+" in (raw or "")
    digits = _digits(raw)
    out: dict = {"ok": False, "notes": []}
    if not (7 <= len(digits) <= 15):
        out["error"] = "not a plausible phone number (needs 7-15 digits)"
        return out

    code, national, iso2 = _split_e164(digits, had_plus)

    # A trunk prefix written after the country code ("+44 (0)20 7946 0958") is
    # NOT part of the E.164 number. Left in, it produced an invalid e164 and a
    # "00..." national format. Italy and friends genuinely keep the zero.
    trunk_stripped = False
    if code and code != "1" and code not in _KEEPS_LEADING_ZERO and national.startswith("0"):
        national = national.lstrip("0") or national
        trunk_stripped = True

    if code == "1":
        # Only a full 10-digit national number is a real NANP number. Anything
        # else used to be force-fed through digits[-10:], which SILENTLY
        # RENDERED A DIFFERENT PHONE NUMBER (the country code got shifted into
        # the area code). Report it as malformed instead of inventing one.
        if len(national) != 10:
            out["ok"] = True
            out["valid"] = False
            out["country"] = {"name": "United States / Canada (NANP)", "iso2": "",
                              "flag": "", "calling_code": "1"}
            out["number_type"] = "Unknown"
            out["e164"] = None
            out["national_format"] = digits
            out["international_format"] = None
            out["notes"].append(
                f"a +1 number needs exactly 10 digits after the country code; this has "
                f"{len(national)}, so it is not a valid North American number")
            return out
        out["e164"] = "+1" + national
        npa = area_code or national[:3]
        nxx = national[3:6]
        # Country within NANP: Caribbean/other by area code, Canada by set, else US.
        if npa in _NANP_COUNTRY:
            name, cc_iso = _NANP_COUNTRY[npa]
        elif npa in _CANADA_NPA:
            name, cc_iso = "Canada", "CA"
        else:
            name, cc_iso = "United States", "US"
        out["country"] = {"name": name, "iso2": cc_iso, "flag": _flag(cc_iso), "calling_code": "1"}

        line_type, lt_note = _nanp_line_type(npa, nxx) if npa else ("Unknown", None)
        out["number_type"] = line_type
        if lt_note:
            out["notes"].append(lt_note)

        nat_fmt, intl_fmt = _nanp_format(national)
        out["national_format"] = nat_fmt
        out["international_format"] = intl_fmt

        nanp: dict = {"area_code": npa or None, "kind": "toll-free" if npa in _TOLL_FREE else
                      ("premium" if npa == "900" else "geographic")}
        if name == "United States" and us_region:
            nanp["region"] = us_region
            exact = npa in _NPA_ZONE_OVERRIDE   # this area code's zone is known outright
            zone = _NPA_ZONE_OVERRIDE.get(npa) or _STATE_ZONE.get(us_region)
            if zone:
                nanp["timezone"] = zone
                lt = _local_time(zone)
                if lt:
                    nanp["local_time"] = lt
                # Only hedge when we're actually guessing from the state's
                # dominant zone. An area code with an explicit override is
                # exact, and flagging it "approx." contradicted the override.
                if us_region in _SPLIT_TZ_STATES and not exact:
                    nanp["timezone_approx"] = True
                    out["notes"].append(f"{us_region} spans more than one US time zone; local time shown is the dominant zone")
        elif name == "Canada":
            out["notes"].append("Canadian area code; region/time zone not resolved offline")
        out["nanp"] = nanp
        # Structural validity for a geographic NANP number.
        if npa and nxx:
            out["valid"] = bool(re.match(r"[2-9]\d\d", npa) and re.match(r"[2-9]\d\d", nxx) and len(national) == 10)
        out["ok"] = True
        return out

    # International (non-NANP).
    if code and code in _CC:
        name, cc_iso = _CC[code]
        # +7 is shared: Kazakhstan uses national numbers starting 6 or 7,
        # Russia 3/4/5/8/9. Without this every Kazakh number flew a Russian flag.
        if code == "7" and national[:1] in _PLUS7_KZ_FIRST_DIGITS:
            name, cc_iso = "Kazakhstan", "KZ"
        out["country"] = {"name": name, "iso2": cc_iso, "flag": _flag(cc_iso), "calling_code": code}
        out["e164"] = "+" + code + national
        out["international_format"] = _intl_format(code, national)
        # Do NOT invent a trunk prefix. Most of the world writes a leading 0
        # domestically, but plenty of countries (Spain, Portugal, Denmark,
        # Norway, Iceland, Greece, Poland, Czechia...) have none at all, and
        # Russia uses 8. Showing the national significant number ungrouped-by-
        # guesswork is honest; inventing a "0" is just wrong for those.
        out["national_format"] = " ".join(_intl_format(code, national).split(" ")[1:]) or national
        out["number_type"] = "Unknown"
        if trunk_stripped:
            out["notes"].append("a trunk '0' written after the country code was dropped; "
                                "it is not part of the international number")
        out["notes"].append("line type and carrier for international numbers need a keyed lookup (add a NumLookup or IPQualityScore key in Settings)")
        # ITU E.164 caps the whole number (country code included) at 15 digits;
        # below ~8 total it isn't a dialable international number.
        out["valid"] = 8 <= len(code + national) <= 15
        out["ok"] = True
        return out

    # Couldn't place a country code. We genuinely do not know whether this is
    # valid -- the old `7 <= len(digits) <= 15` was a tautology here (the guard
    # at the top already enforced it), so every unplaceable string was stamped
    # "Valid: yes".
    out["country"] = None
    out["number_type"] = "Unknown"
    out["national_format"] = digits
    out["valid"] = None
    out["notes"].append("could not match a country calling code, so this could not be validated; "
                        "showing the parsed digits only")
    out["ok"] = True
    return out
