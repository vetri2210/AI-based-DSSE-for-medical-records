"""Offline, rule-based medical query expansion.

This module receives only plaintext query text. It has no access to application
configuration, database connections, encryption keys, or search tokens.
"""

import re


_WORD_PATTERN = re.compile(r"[a-z]+")
_MAX_QUERY_LENGTH = 500
_MAX_EXPANSION_TERMS = 32

_PHRASE_EXPANSIONS = {
    "high blood sugar": ("diabetes", "glucose", "hyperglycemia", "insulin"),
    "blood sugar": ("glucose", "glycemia"),
    "heart attack": ("myocardial", "infarction"),
    "high blood pressure": ("hypertension",),
    "low blood sugar": ("hypoglycemia", "glucose"),
    "kidney disease": ("renal", "nephropathy"),
    "chest pain": ("angina", "cardiac"),
    "shortness of breath": ("dyspnea",),
}

_TERM_EXPANSIONS = {
    "diabetes": ("glucose", "hyperglycemia", "insulin"),
    "diabetic": ("diabetes", "glucose", "insulin"),
    "hyperglycemia": ("diabetes", "glucose"),
    "glucose": ("blood", "sugar"),
    "hypertension": ("blood", "pressure"),
    "renal": ("kidney",),
    "nephropathy": ("kidney", "renal"),
    "myocardial": ("heart",),
    "infarction": ("heart", "attack"),
    "angina": ("chest", "pain"),
    "dyspnea": ("breath",),
}


def normalize_query_terms(query: str) -> list[str]:
    """Return unique lowercase alphabetic terms in their original order."""
    if not isinstance(query, str):
        raise TypeError("query must be a string")
    if len(query) > _MAX_QUERY_LENGTH:
        raise ValueError("query is too long")
    terms = []
    seen = set()
    for term in _WORD_PATTERN.findall(query.casefold()):
        if term not in seen:
            terms.append(term)
            seen.add(term)
    return terms


def expand_query(query: str) -> list[str]:
    """Return normalized original words plus controlled medical related terms."""
    original_terms = normalize_query_terms(query)
    if not original_terms:
        return []

    expanded = list(original_terms)
    seen = set(expanded)

    normalized_query = " ".join(original_terms)
    for phrase, terms in _PHRASE_EXPANSIONS.items():
        if phrase in normalized_query:
            for term in terms:
                if term not in seen:
                    expanded.append(term)
                    seen.add(term)

    for original in original_terms:
        for term in _TERM_EXPANSIONS.get(original, ()):
            if term not in seen:
                expanded.append(term)
                seen.add(term)
            if len(expanded) >= _MAX_EXPANSION_TERMS:
                return expanded[:_MAX_EXPANSION_TERMS]

    return expanded[:_MAX_EXPANSION_TERMS]
