"""
Logique d'analyse IOC + persistance ScanHistory, partagée entre
/ioc/analyze, /ioc/bulk et le chat.
"""
from __future__ import annotations

import re
from typing import Any

from sqlalchemy.orm import Session

from database.models import ScanHistory
from rag.rag_retriever import retrieve
from services.cve_service import get_cve_report
from services.ioc_analysis import analyze_ioc
from services.llm_enricher import enrich_ioc, enrich_with_rag, _fallback
from services.rag_gate import should_disable_rag, build_rag_query, collect_ti_signals


def detect_type(indicator: str) -> str:
    indicator = indicator.strip()
    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", indicator):
        return "ip"
    if re.match(r"^CVE-\d{4}-\d{4,}$", indicator.upper()):
        return "cve"
    if re.match(r"^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{63,64}$", indicator):
        return "hash"
    if re.match(r"^https?://", indicator):
        return "url"
    if re.match(r"^[\w\.-]+@[\w\.-]+\.[a-z]{2,}$", indicator):
        return "mail"
    if re.match(r"^[\w\.-]+\.[a-z]{2,}$", indicator):
        return "domain"
    return "unknown"


def _normalize_ti_cve(raw: dict, indicator: str, ioc_type: str) -> dict:
    ti = {"indicator": indicator, "type": ioc_type}
    risk = raw.get("risk", {})
    ti.update(
        {
            "cve_id": raw.get("cve_id"),
            "severity": raw.get("severity", "N/A"),
            "cvss_score": raw.get("cvss_score"),
            "cvss_vector": raw.get("cvss_vector"),
            "cwe": raw.get("cwe", []),
            "published": raw.get("published"),
            "risk_level": risk.get("level", "unknown"),
            "affected": raw.get("affected", []),
            "description": raw.get("description", ""),
        }
    )
    return ti


def _save_scan(
    db: Session,
    user_id: int,
    indicator: str,
    ioc_type: str,
    llm_result: dict,
):
    scan = ScanHistory(
        user_id=user_id,
        indicator=indicator,
        ioc_type=ioc_type,
        risk_level=llm_result.get("threat_level", "unknown"),
        risk_score=llm_result.get("score", 0),
        confidence=llm_result.get("confidence", "medium"),
        source="ioc_analyze",
        final_verdict=llm_result.get("threat_level", "unknown"),
    )
    db.add(scan)
    db.commit()


def analyze_indicator_for_user(
    db: Session,
    user_id: int,
    indicator: str,
    force_rag: bool = False,
) -> dict[str, Any]:
    """
    Retourne {"ok": True, "payload": dict} ou {"ok": False, "status_code": int, "error": dict}.
    """
    indicator = indicator.strip()
    if not indicator:
        return {"ok": False, "status_code": 400, "error": {"error": "Indicateur manquant"}}

    ioc_type = detect_type(indicator)

    if ioc_type not in ("ip", "domain", "hash", "url", "mail", "cve"):
        return {
            "ok": False,
            "status_code": 400,
            "error": {"error": f"Type non supporté : {ioc_type}"},
        }

    if ioc_type in ("ip", "domain", "hash", "url", "mail"):
        try:
            payload = analyze_ioc(indicator, ioc_type, force_rag=force_rag)
        except Exception as e:
            return {
                "ok": False,
                "status_code": 500,
                "error": {"error": f"Erreur collecte TI : {str(e)}"},
            }
        if "error" in payload:
            err = str(payload["error"])
            status = 500 if "réponse invalide" in err.lower() else 400
            return {"ok": False, "status_code": status, "error": {"error": payload["error"]}}

        llm = payload.get("llm_analysis", {})
        _save_scan(db, user_id, indicator, ioc_type, llm)
        return {"ok": True, "payload": payload}

    try:
        raw = get_cve_report(indicator)
    except Exception as e:
        return {
            "ok": False,
            "status_code": 500,
            "error": {"error": f"Erreur collecte TI : {str(e)}"},
        }
    if not raw or not isinstance(raw, dict):
        return {
            "ok": False,
            "status_code": 500,
            "error": {"error": f"Service TI a retourné une réponse invalide pour {indicator}"},
        }
    if "error" in raw:
        return {"ok": False, "status_code": 400, "error": {"error": raw["error"]}}

    ti_data = _normalize_ti_cve(raw, indicator, ioc_type)
    final_verdict = raw.get("final_verdict") or raw.get("global_risk_level", "unknown")

    ti_signals = collect_ti_signals(ioc_type, raw)
    rag_docs: list = []
    rag_fetch_error: str | None = None
    skip_rag, rag_gate_reason = should_disable_rag(ioc_type, raw, ti_signals)
    if force_rag:
        skip_rag = False

    if skip_rag:
        print(f"[RAG] Désactivé ({rag_gate_reason}) — signaux: {ti_signals}")
    else:
        try:
            rag_query = build_rag_query(ioc_type, raw, ti_data)
            rag_docs = retrieve(
                query=rag_query,
                k=5,
                min_score=0.52,
                ioc_type=ioc_type,
            )
        except Exception as e:
            rag_docs = []
            rag_fetch_error = str(e)
            print(f"[RAG] Erreur : {e}")

    try:
        if rag_docs:
            llm_result = enrich_with_rag(
                ioc=indicator,
                ioc_type=ioc_type,
                final_verdict=final_verdict,
                rag_docs=rag_docs,
                ti_data=ti_data,
            )
        else:
            llm_result = enrich_ioc(ioc_type, raw)

        if "error" in llm_result or not llm_result.get("threat_level"):
            llm_result = _fallback(ti_data, reason=llm_result.get("error", "réponse LLM incomplète"))

    except Exception as e:
        llm_result = {
            "threat_level": "unknown",
            "score": 0,
            "summary": f"LLM indisponible : {str(e)}",
            "tags": [],
            "recommandation": "Analyse manuelle requise.",
            "fallback": True,
        }

    _save_scan(db, user_id, indicator, ioc_type, llm_result)

    payload = {
        "indicator": indicator,
        "type": ioc_type,
        "ti_data": {
            "source": raw.get("source"),
            "description": raw.get("description"),
            "severity": raw.get("severity"),
            "cvss_score": raw.get("cvss_score"),
            "cvss_v2_score": raw.get("cvss_v2_score"),
            "cvss_vector": raw.get("cvss_vector"),
            "published": raw.get("published"),
            "last_modified": raw.get("last_modified"),
            "cwe": raw.get("cwe", []),
            "affected": raw.get("affected", []),
            "references": raw.get("references", []),
            "final_verdict": raw.get("risk", {}).get("level"),
        },
        "rag_context": [
            {"text": r["text"], "source": r["source"], "score": r["score"]}
            for r in rag_docs
        ]
        if rag_docs
        else [],
        "llm_analysis": {
            "threat_level": llm_result.get("threat_level"),
            "score": llm_result.get("score"),
            "summary": llm_result.get("summary"),
            "tags": llm_result.get("tags", []),
            "recommended_action": llm_result.get("recommandation"),
            "model": llm_result.get("model_used"),
            "rag_used": llm_result.get("rag_used", False),
            "fallback": llm_result.get("fallback", False),
            "rag_skipped": skip_rag,
            "rag_skip_reason": rag_gate_reason if skip_rag else None,
            "rag_fetch_error": rag_fetch_error,
        },
    }
    return {"ok": True, "payload": payload}
