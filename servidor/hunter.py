import httpx
import asyncio
import os
import re
import json
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

# ─── LOGGER ───────────────────────────────────────────────────────────────────

class VynexLogger:
    @staticmethod
    def info(msg):    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔵 [INFO]    {msg}")
    @staticmethod
    def success(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟢 [SUCCESS] {msg}")
    @staticmethod
    def warn(msg):    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟡 [WARN]    {msg}")
    @staticmethod
    def error(msg, detail=""):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔴 [ERROR]   {msg}" + (f" | {detail}" if detail else ""))

# ─── HUNTER ───────────────────────────────────────────────────────────────────

class NpmProtectHunter:
    def __init__(self):
        self.vt_keys = [k for k in [os.getenv("VT_API_KEY1"), os.getenv("VT_API_KEY2")] if k]
        self.current_key_idx = 0
        self.base_url_vt = "https://www.virustotal.com/api/v3"

    @property
    def vt_key(self):
        return self.vt_keys[self.current_key_idx]

    async def fetch_hashes(self):
        VynexLogger.info("Sincronizando feeds de malwares ativos...")
        try:
            async with httpx.AsyncClient(follow_redirects=True) as client:
                resp = await client.get(
                    "https://bazaar.abuse.ch/export/txt/sha256/recent/",
                    timeout=15.0
                )
                hashes = list(set(re.findall(r'\b([a-fA-F0-9]{64})\b', resp.text)))
                VynexLogger.info(f"{len(hashes)} hashes unicos obtidos.")
                return hashes
        except Exception as e:
            VynexLogger.error("Falha ao obter feed", str(e))
            return []

    async def get_vt_data(self, file_hash):
        """Busca metadados completos do arquivo no VirusTotal."""
        url = f"{self.base_url_vt}/files/{file_hash}"
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.get(url, headers={"x-apikey": self.vt_key}, timeout=15.0)
                if resp.status_code != 200:
                    return None
                d = resp.json().get("data", {}).get("attributes", {})
                stats = d.get("last_analysis_stats", {})
                return {
                    "name":         d.get("meaningful_name") or d.get("names", [None])[0] or "Unknown",
                    "type":         d.get("type_description", "Unknown"),
                    "size":         d.get("size", 0),
                    "malicious":    stats.get("malicious", 0),
                    "suspicious":   stats.get("suspicious", 0),
                    "harmless":     stats.get("harmless", 0),
                    "undetected":   stats.get("undetected", 0),
                    "tags":         d.get("tags", []),
                    "magic":        d.get("magic", ""),
                    "first_seen":   d.get("first_submission_date", ""),
                    "last_seen":    d.get("last_analysis_date", ""),
                    "times_submitted": d.get("times_submitted", 0),
                    "signature":    d.get("signature_info", {}).get("description", ""),
                    "pe_info":      d.get("pe_info", {}),
                    "popular_threat": d.get("popular_threat_classification", {}).get("suggested_threat_label", ""),
                    "sandbox_verdicts": list(d.get("sandbox_verdicts", {}).keys())[:5],
                }
            except Exception as e:
                VynexLogger.error("Erro ao buscar dados VT", str(e))
                return None

    async def post_to_vt(self, file_hash, comment_text):
        url = f"{self.base_url_vt}/files/{file_hash}/comments"
        payload = {
            "data": {
                "type": "comment",
                "attributes": {
                    "text": comment_text[:3500].replace('"', "'").replace('\\', '/')
                }
            }
        }
        headers = {"x-apikey": self.vt_key, "Content-Type": "application/json"}
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(url, headers=headers, json=payload, timeout=20.0)
                if resp.status_code == 200:
                    VynexLogger.success("Publicado no VirusTotal!")
                    return True
                else:
                    VynexLogger.warn(f"VT retornou {resp.status_code}: {resp.text[:120]}")
                    return False
            except Exception as e:
                VynexLogger.error("Erro no POST VT", str(e))
                return False

# ─── IA — SCORE DE SEVERIDADE ─────────────────────────────────────────────────

async def get_severity_score(file_hash: str, analysis: str, vt: dict) -> int:
    """Gera score de severidade 0-100 baseado nos dados reais do VT + relatorio."""
    prompt = (
        f"Baseado nos seguintes dados de malware, retorne SOMENTE um numero inteiro de 0 a 100 "
        f"(0=inofensivo, 100=critico/destrutivo). Sem texto, sem explicacao, apenas o numero.\n\n"
        f"Deteccoes VT: {vt['malicious']} maliciosas, {vt['suspicious']} suspeitas\n"
        f"Tipo: {vt['type']}\n"
        f"Ameaca: {vt['popular_threat'] or 'desconhecida'}\n"
        f"Tags: {', '.join(vt['tags'][:5]) if vt['tags'] else 'nenhuma'}\n\n"
        f"Trecho do relatorio:\n{analysis[:1500]}"
    )
    try:
        resp = await ai_client.chat.completions.create(
            model="google/gemini-2.0-flash-lite-001",
            messages=[{"role": "user", "content": prompt}]
        )
        raw = resp.choices[0].message.content.strip()
        score = int(re.search(r'\d+', raw).group())
        return max(0, min(100, score))  # garante que fica entre 0-100
    except:
        return 50  # fallback neutro

def score_label(score: int) -> tuple:
    """Retorna (emoji, label, cor_discord) baseado no score."""
    if score >= 80: return ("🔴", "CRITICAL", 0xFF1A1A)
    if score >= 60: return ("🟠", "HIGH",     0xFF8C00)
    if score >= 40: return ("🟡", "MEDIUM",   0xFFD700)
    return                 ("🟢", "LOW",      0x00FF88)

# ─── DISCORD ──────────────────────────────────────────────────────────────────

async def notify_discord(file_hash: str, report_id: int, score: int, analysis: str):
    """Envia embed estilizado no Discord com os detalhes do malware."""
    if not DISCORD_WEBHOOK:
        return

    emoji, label, color = score_label(score)
    preview = analysis[:300].replace('`', "'") + "..."

    embed = {
        "title": f"{emoji} Novo Malware Detectado — Severidade {label}",
        "color": color,
        "fields": [
            {"name": "🔑 SHA-256", "value": f"`{file_hash}`", "inline": False},
            {"name": "📊 Score",   "value": f"**{score}/100** — {label}", "inline": True},
            {"name": "🆔 Report",  "value": f"ID #{report_id}", "inline": True},
            {"name": "📄 Preview", "value": preview, "inline": False},
        ],
        "footer": {
            "text": "NpmProtect Intel · Vynex Labs",
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url": "https://npmprotect.vercel.app",
    }

    payload = {
        "username": "NpmProtect Intel",
        "embeds": [embed]
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(DISCORD_WEBHOOK, json=payload, timeout=10.0)
            if resp.status_code in (200, 204):
                VynexLogger.success("Notificacao enviada para o Discord!")
            else:
                VynexLogger.warn(f"Discord retornou {resp.status_code}")
        except Exception as e:
            VynexLogger.error("Erro ao notificar Discord", str(e))

# ─── SUPABASE ─────────────────────────────────────────────────────────────────

async def already_in_db(file_hash) -> bool:
    try:
        result = supabase.table("reports").select("hash").eq("hash", file_hash).execute()
        return len(result.data) > 0
    except:
        return False

async def save_to_supabase(file_hash, report_id, content, score):
    try:
        supabase.table("reports").insert({
            "hash":      file_hash,
            "report_id": str(report_id),
            "content":   content,
            "analyst":   "Mozart_Dev",
            "score":     score,
        }).execute()
        VynexLogger.success("Dados sincronizados com o Banco de Dados (Realtime Ativo).")
    except Exception as e:
        VynexLogger.error("Erro ao salvar no Supabase", str(e))

# ─── VT COMMENT ──────────────────────────────────────────────────────────────────

def build_vt_comment(h, report_id, score, vt, analysis):
    emoji, label, _ = score_label(score)
    total = vt["malicious"] + vt["suspicious"] + vt["harmless"] + vt["undetected"]
    threat = vt["popular_threat"] or vt["type"] or "Unknown"

    # Extrai o Executive Summary do relatorio
    summary = ""
    for line in analysis.splitlines():
        if "executive summary" in line.lower():
            continue
        if line.startswith("##") and "summary" not in line.lower():
            break
        if line.strip() and not line.startswith("#"):
            summary += line.strip() + " "
        if len(summary) > 400:
            break

    lines = [
        "🛡️ NpmProtect Intel Report #" + str(report_id),
        emoji + " Severity: " + str(score) + "/100 — " + label,
        "",
        "📋 File: " + vt["name"],
        "🔬 Type: " + vt["type"],
        "🚨 Detections: " + str(vt["malicious"]) + "/" + str(total) + " engines",
        "☠️  Threat: " + threat,
        "🏷️  Tags: " + (", ".join(vt["tags"][:4]) if vt["tags"] else "none"),
        "",
        "📝 Summary:",
        summary.strip()[:500],
        "",
        "🔗 Full Report: https://npmprotect.vercel.app",
        "🔍 To view the complete analysis, visit https://npmprotect.vercel.app and search for:",
        h,
        "",
        "Analyst: Mozart_Dev | NpmProtect Security Engine © 2026",
    ]
    return "\n".join(lines)[:3000]

# ─── MAIN ─────────────────────────────────────────────────────────────────────

async def main():
    hunter = NpmProtectHunter()
    VynexLogger.info("NpmProtect v7.0 | Vynex Cloud Edition Online")

    all_hashes = await hunter.fetch_hashes()
    if not all_hashes:
        return

    random.shuffle(all_hashes)

    for h in all_hashes:

        if await already_in_db(h):
            VynexLogger.info(f"Ja catalogado, pulando: {h[:16]}...")
            continue

        VynexLogger.info(f"Monitorando: {h}")

        vt = await hunter.get_vt_data(h)
        if not vt:
            VynexLogger.warn("Hash nao indexado no VT (404). Pulando...")
            continue

        VynexLogger.success(f"Alvo confirmado | {vt['malicious']} engines maliciosas | {vt['popular_threat'] or vt['type']}")

        report_id = random.randint(1000, 9999)
        total_engines = vt['malicious'] + vt['suspicious'] + vt['harmless'] + vt['undetected']
        first_seen_fmt = vt['first_seen'] if vt['first_seen'] else 'Unknown'
        size_mb = round(vt['size'] / 1024 / 1024, 2) if vt['size'] else 0
        threat = vt['popular_threat'] or vt['type'] or 'Unknown'
        tags_str = ', '.join(vt['tags'][:6]) if vt['tags'] else 'none'
        sandboxes_str = ', '.join(vt['sandbox_verdicts']) if vt['sandbox_verdicts'] else 'none'
        sig = vt['signature'] or 'UNSIGNED'

        prompt = f"""You are a senior malware analyst at NpmProtect Security Labs. Generate a professional, structured malware analysis report in Markdown using EXACTLY this format:

---

# 🛡️ MALWARE ANALYSIS REPORT: NpmProtect Security Engine

**Date:** {first_seen_fmt}
**Analyst:** Mozart_Dev (Analyst ID: {report_id})
**Security Level:** [choose: Critical 🔴 / High 🟠 / Medium 🟡 / Low 🟢 / False Positive 🟡 — based on detection count]

---

## 1. Executive Summary
[2-3 sentences: what this malware is, what it does, and its threat level. Be specific based on the data provided.]

---

## 2. File Metadata

| Attribute | Technical Data |
|---|---|
| File Name | {vt['name']} |
| File Size | {size_mb} MB ({vt['size']} bytes) |
| Type | {vt['type']} |
| SHA-256 | {h} |
| Magic | {vt['magic'] or 'N/A'} |
| Signature | {sig} |
| First Seen | {first_seen_fmt} |
| Times Submitted | {vt['times_submitted']} |
| Tags | {tags_str} |

---

## 3. Detection Metrics

NpmProtect cross-referenced this sample with {total_engines} global security databases.

**Detection Score: {vt['malicious']} / {total_engines}**

| Engine | Verdict |
|---|---|
[List 4-6 notable AV verdicts based on threat type — invent realistic engine names and results consistent with the detection count]

---

## 4. Behavioral Analysis

### 📂 File System Activity
[Describe likely file system changes based on malware type]

### 🔑 Registry Activity
[Describe registry modifications — include MITRE technique ID]

### 🌐 Network Activity
[Describe C2 or network behavior — include suspicious domains/IPs if malicious]

---

## 5. MITRE ATT&CK Matrix

| Tactic | Technique ID | Description |
|---|---|---|
[Minimum 5 rows — use real MITRE techniques consistent with the malware type: {threat}]

---

## 6. IOCs

[List indicators: hashes, IPs, domains, registry keys, file paths relevant to this threat]

---

## 7. Final Verdict & Recommendation

**Verdict:** [MALICIOUS / SUSPICIOUS / CLEAN]

[2-3 sentences with analyst recommendation and action taken]

---

*SIGNED BY: NpmProtect — Digital Security Division*
*Lead Analyst ID: {report_id} | Copyright © 2026 NpmProtect Labs*

---

REAL DATA TO USE:
- Hash: {h}
- Detections: {vt['malicious']} malicious / {vt['suspicious']} suspicious / {vt['undetected']} undetected
- Threat label: {threat}
- Sandboxes flagged: {sandboxes_str}

Rules: Use ONLY Markdown. No double quotes. Max 4000 characters. Fill every section.
"""


        try:
            ai_resp = await ai_client.chat.completions.create(
                model="google/gemini-2.0-flash-lite-001",
                messages=[{"role": "user", "content": prompt}]
            )
            analysis = ai_resp.choices[0].message.content.strip()
            VynexLogger.success("Inteligencia Reforcada gerada.")

            # Score de severidade gerado pela IA
            score = await get_severity_score(h, analysis, vt)
            emoji, label, _ = score_label(score)
            VynexLogger.info(f"Score de severidade: {score}/100 {emoji} {label}")

            # 1. Publica no VT com comentario curto e estruturado
            vt_comment = build_vt_comment(h, report_id, score, vt, analysis)
            await hunter.post_to_vt(h, vt_comment)

            # 2. Salva no Supabase com o score
            await save_to_supabase(h, report_id, analysis, score)

            # 3. Notifica Discord
            await notify_discord(h, report_id, score, analysis)

            VynexLogger.info("Ciclo completo. Cooldown de 45s...\n")
            await asyncio.sleep(45)

        except Exception as e:
            VynexLogger.error("Falha no processamento", str(e))


if __name__ == "__main__":
    asyncio.run(main())
