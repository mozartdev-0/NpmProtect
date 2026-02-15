import httpx
import asyncio
import os
import re
import random
from datetime import datetime, timezone
from openai import AsyncOpenAI
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

# ─── CLIENTES ─────────────────────────────────────────────────────────────────

ai_client = AsyncOpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY"),
)

supabase: Client = create_client(
    os.getenv("SUPABASE_URL"),
    os.getenv("SUPABASE_SERVICE_ROLE"),
)

DISCORD_WEBHOOK = os.getenv("DISCORD_WEBHOOK")
AI_MODEL        = "google/gemini-2.0-flash-lite-001"
COOLDOWN        = int(os.getenv("COOLDOWN_SECONDS", 45))

# ─── LOGGER ───────────────────────────────────────────────────────────────────

class Log:
    _fmt = lambda self, t: datetime.now().strftime("%H:%M:%S")
    def info(self, m):    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔵 [INFO]    {m}")
    def success(self, m): print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟢 [SUCCESS] {m}")
    def warn(self, m):    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟡 [WARN]    {m}")
    def error(self, m, d=""): print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔴 [ERROR]   {m}" + (f" | {d}" if d else ""))

log = Log()

# ─── SCORE ────────────────────────────────────────────────────────────────────

def score_label(score: int) -> tuple[str, str, int]:
    if score >= 80: return "🔴", "CRITICAL", 0xFF1A1A
    if score >= 60: return "🟠", "HIGH",     0xFF8C00
    if score >= 40: return "🟡", "MEDIUM",   0xFFD700
    return                 "🟢", "LOW",      0x00FF88

# ─── HUNTER ───────────────────────────────────────────────────────────────────

class NpmProtectHunter:
    BASE_VT = "https://www.virustotal.com/api/v3"

    def __init__(self):
        self.vt_keys = [k for k in [os.getenv("VT_API_KEY1"), os.getenv("VT_API_KEY2")] if k]
        self._key_idx = 0

    @property
    def vt_key(self) -> str:
        return self.vt_keys[self._key_idx % len(self.vt_keys)]

    async def fetch_hashes(self) -> list[str]:
        log.info("Sincronizando feed MalwareBazaar...")
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as c:
                r = await c.get("https://bazaar.abuse.ch/export/txt/sha256/recent/")
                hashes = list(set(re.findall(r'\b([a-fA-F0-9]{64})\b', r.text)))
                log.info(f"{len(hashes)} hashes únicos obtidos.")
                return hashes
        except Exception as e:
            log.error("Falha ao obter feed", str(e))
            return []

    async def get_vt_data(self, file_hash: str) -> dict | None:
        try:
            async with httpx.AsyncClient(timeout=15.0) as c:
                r = await c.get(
                    f"{self.BASE_VT}/files/{file_hash}",
                    headers={"x-apikey": self.vt_key}
                )
                if r.status_code != 200:
                    return None
                d = r.json().get("data", {}).get("attributes", {})
                s = d.get("last_analysis_stats", {})
                return {
                    "name":             d.get("meaningful_name") or (d.get("names") or [None])[0] or "Unknown",
                    "type":             d.get("type_description", "Unknown"),
                    "size":             d.get("size", 0),
                    "malicious":        s.get("malicious", 0),
                    "suspicious":       s.get("suspicious", 0),
                    "harmless":         s.get("harmless", 0),
                    "undetected":       s.get("undetected", 0),
                    "tags":             d.get("tags", []),
                    "magic":            d.get("magic", ""),
                    "first_seen":       d.get("first_submission_date", ""),
                    "times_submitted":  d.get("times_submitted", 0),
                    "signature":        d.get("signature_info", {}).get("description", ""),
                    "popular_threat":   d.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                    "sandbox_verdicts": list(d.get("sandbox_verdicts", {}).keys())[:5],
                }
        except Exception as e:
            log.error("Erro ao buscar dados VT", str(e))
            return None

    async def post_to_vt(self, file_hash: str, comment: str) -> bool:
        payload = {"data": {"type": "comment", "attributes": {
            "text": comment[:3500].replace('"', "'").replace("\\", "/")
        }}}
        try:
            async with httpx.AsyncClient(timeout=20.0) as c:
                r = await c.post(
                    f"{self.BASE_VT}/files/{file_hash}/comments",
                    headers={"x-apikey": self.vt_key, "Content-Type": "application/json"},
                    json=payload
                )
                if r.status_code == 200:
                    log.success("Publicado no VirusTotal!")
                    return True
                log.warn(f"VT retornou {r.status_code}: {r.text[:120]}")
                return False
        except Exception as e:
            log.error("Erro no POST VT", str(e))
            return False

# ─── IA ───────────────────────────────────────────────────────────────────────

async def generate_report(h: str, report_id: int, vt: dict) -> str:
    total    = vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt["undetected"]
    size_mb  = round(vt["size"] / 1024 / 1024, 2) if vt["size"] else 0
    threat   = vt["popular_threat"] or vt["type"] or "Unknown"
    tags     = ", ".join(vt["tags"][:6]) if vt["tags"] else "none"
    boxes    = ", ".join(vt["sandbox_verdicts"]) if vt["sandbox_verdicts"] else "none"
    sig      = vt["signature"] or "UNSIGNED"
    seen     = vt["first_seen"] or "Unknown"

    prompt = f"""You are a senior malware analyst at NpmProtect Security Labs. Generate a professional structured malware analysis report in Markdown using EXACTLY this format:

---

# 🛡️ MALWARE ANALYSIS REPORT: NpmProtect Security Engine

**Date:** {seen}
**Analyst:** Mozart_Dev (Analyst ID: {report_id})
**Security Level:** [Critical 🔴 / High 🟠 / Medium 🟡 / Low 🟢 — based on detection count]

---

## 1. Executive Summary
[2-3 sentences describing what this malware is, behavior, and threat level. Be specific.]

---

## 2. File Metadata

| Attribute | Technical Data |
|---|---|
| File Name | {vt["name"]} |
| File Size | {size_mb} MB ({vt["size"]} bytes) |
| Type | {vt["type"]} |
| SHA-256 | {h} |
| Magic | {vt["magic"] or "N/A"} |
| Signature | {sig} |
| First Seen | {seen} |
| Times Submitted | {vt["times_submitted"]} |
| Tags | {tags} |

---

## 3. Detection Metrics

NpmProtect cross-referenced this sample with {total} global security databases.

**Detection Score: {vt["malicious"]} / {total}**

| Engine | Verdict |
|---|---|
[List 5 realistic AV engine names and verdicts consistent with the detection count]

---

## 4. Behavioral Analysis

### 📂 File System Activity
[Describe file system changes based on malware type]

### 🔑 Registry Activity
[Registry modifications with MITRE technique ID]

### 🌐 Network Activity
[C2 behavior, suspicious domains/IPs if malicious]

---

## 5. MITRE ATT&CK Matrix

| Tactic | Technique ID | Description |
|---|---|---|
[Minimum 5 rows consistent with threat type: {threat}]

---

## 6. IOCs

[Hashes, IPs, domains, registry keys, file paths]

---

## 7. Final Verdict & Recommendation

**Verdict:** [MALICIOUS / SUSPICIOUS / CLEAN]

[2-3 sentences with analyst recommendation.]

---

*SIGNED BY: NpmProtect — Digital Security Division*
*Lead Analyst ID: {report_id} | Copyright © 2026 NpmProtect Labs*

---

DATA:
- Hash: {h}
- Detections: {vt["malicious"]} malicious / {vt["suspicious"]} suspicious / {vt["undetected"]} undetected
- Threat: {threat}
- Sandboxes: {boxes}

Rules: Markdown only. No double quotes. Max 4000 characters. Fill every section.
"""
    resp = await ai_client.chat.completions.create(
        model=AI_MODEL,
        messages=[{"role": "user", "content": prompt}]
    )
    return resp.choices[0].message.content.strip()


async def generate_score(analysis: str, vt: dict) -> int:
    prompt = (
        f"Based on these malware data, return ONLY an integer 0-100 "
        f"(0=harmless, 100=critical/destructive). No text, just the number.\n\n"
        f"VT detections: {vt['malicious']} malicious, {vt['suspicious']} suspicious\n"
        f"Type: {vt['type']}\n"
        f"Threat: {vt['popular_threat'] or 'unknown'}\n"
        f"Tags: {', '.join(vt['tags'][:5]) if vt['tags'] else 'none'}\n\n"
        f"Report excerpt:\n{analysis[:1500]}"
    )
    try:
        resp = await ai_client.chat.completions.create(
            model=AI_MODEL,
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.choices[0].message.content.strip()
        return max(0, min(100, int(re.search(r'\d+', raw).group())))
    except:
        return 50

# ─── VT COMMENT ───────────────────────────────────────────────────────────────

def build_vt_comment(h: str, report_id: int, score: int, vt: dict, analysis: str) -> str:
    emoji, label, _ = score_label(score)
    total  = vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt["undetected"]
    threat = vt["popular_threat"] or vt["type"] or "Unknown"

    summary = ""
    for line in analysis.splitlines():
        if "executive summary" in line.lower(): continue
        if line.startswith("##") and "summary" not in line.lower(): break
        if line.strip() and not line.startswith("#"):
            summary += line.strip() + " "
        if len(summary) > 400: break

    return "\n".join([
        f"🛡️ NpmProtect Intel Report #{report_id}",
        f"{emoji} Severity: {score}/100 — {label}",
        "",
        f"📋 File: {vt['name']}",
        f"🔬 Type: {vt['type']}",
        f"🚨 Detections: {vt['malicious']}/{total} engines",
        f"☠️  Threat: {threat}",
        f"🏷️  Tags: {', '.join(vt['tags'][:4]) if vt['tags'] else 'none'}",
        "",
        "📝 Summary:",
        summary.strip()[:500],
        "",
        "🔗 Full Report: https://npmprotect.vercel.app",
        "🔍 To view the complete analysis, visit https://npmprotect.vercel.app and search for:",
        h,
        "",
        "Analyst: Mozart_Dev | NpmProtect Security Engine © 2026",
    ])[:3000]

# ─── DISCORD ──────────────────────────────────────────────────────────────────

async def notify_discord(h: str, report_id: int, score: int, analysis: str):
    if not DISCORD_WEBHOOK:
        return
    emoji, label, color = score_label(score)
    embed = {
        "title":  f"{emoji} Novo Malware Detectado — Severidade {label}",
        "color":  color,
        "url":    "https://npmprotect.vercel.app",
        "fields": [
            {"name": "🔑 SHA-256", "value": f"`{h}`",                          "inline": False},
            {"name": "📊 Score",   "value": f"**{score}/100** — {label}",      "inline": True},
            {"name": "🆔 Report",  "value": f"ID #{report_id}",                "inline": True},
            {"name": "📄 Preview", "value": analysis[:300].replace("`", "'") + "...", "inline": False},
        ],
        "footer":    {"text": "NpmProtect Intel · Vynex Labs"},
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
    try:
        async with httpx.AsyncClient(timeout=10.0) as c:
            r = await c.post(DISCORD_WEBHOOK, json={"username": "NpmProtect Intel", "embeds": [embed]})
            if r.status_code in (200, 204):
                log.success("Notificação enviada para o Discord!")
            else:
                log.warn(f"Discord retornou {r.status_code}")
    except Exception as e:
        log.error("Erro ao notificar Discord", str(e))

# ─── SUPABASE ─────────────────────────────────────────────────────────────────

async def already_in_db(file_hash: str) -> bool:
    try:
        r = supabase.table("reports").select("hash").eq("hash", file_hash).execute()
        return len(r.data) > 0
    except:
        return False

async def save_to_supabase(file_hash: str, report_id: int, content: str, score: int):
    try:
        supabase.table("reports").insert({
            "hash":      file_hash,
            "report_id": str(report_id),
            "content":   content,
            "analyst":   "Mozart_Dev",
            "score":     score,
        }).execute()
        log.success("Dados sincronizados com o Banco de Dados (Realtime Ativo).")
    except Exception as e:
        log.error("Erro ao salvar no Supabase", str(e))

# ─── MAIN ─────────────────────────────────────────────────────────────────────

async def main():
    hunter = NpmProtectHunter()
    log.info("NpmProtect v8.0 | Vynex Cloud Edition Online")

    hashes = await hunter.fetch_hashes()
    if not hashes:
        return

    random.shuffle(hashes)

    for h in hashes:
        if await already_in_db(h):
            log.info(f"Já catalogado, pulando: {h[:16]}...")
            continue

        log.info(f"Monitorando: {h}")

        vt = await hunter.get_vt_data(h)
        if not vt:
            log.warn("Hash não indexado no VT. Pulando...")
            continue

        log.success(f"Alvo confirmado | {vt['malicious']} engines maliciosas | {vt['popular_threat'] or vt['type']}")

        report_id = random.randint(1000, 9999)

        try:
            analysis = await generate_report(h, report_id, vt)
            log.success("Relatório gerado.")

            score = await generate_score(analysis, vt)
            emoji, label, _ = score_label(score)
            log.info(f"Score de severidade: {score}/100 {emoji} {label}")

            comment = build_vt_comment(h, report_id, score, vt, analysis)
            await hunter.post_to_vt(h, comment)
            await save_to_supabase(h, report_id, analysis, score)
            await notify_discord(h, report_id, score, analysis)

            log.info(f"Ciclo completo. Cooldown de {COOLDOWN}s...\n")
            await asyncio.sleep(COOLDOWN)

        except Exception as e:
            log.error("Falha no processamento", str(e))


if __name__ == "__main__":
    asyncio.run(main())
