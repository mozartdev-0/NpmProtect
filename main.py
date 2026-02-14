import httpx
import asyncio
import os
import random
import sys
from datetime import datetime
from openai import AsyncOpenAI
from dotenv import load_dotenv
from supabase import create_client, Client

load_dotenv()

# ─── LOGGER ───────────────────────────────────────────────────────────────────

class VynexLogger:
    @staticmethod
    def info(msg):    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔵 [INFO]    {msg}", flush=True)
    @staticmethod
    def success(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟢 [SUCCESS] {msg}", flush=True)
    @staticmethod
    def warn(msg):    print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟡 [WARN]    {msg}", flush=True)
    @staticmethod
    def error(msg, detail=""):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔴 [ERROR]   {msg}", flush=True)
        if detail:
            print(f"                        ↳ {detail}", flush=True)

log = VynexLogger()

# ─── VALIDAÇÃO DE SECRETS ─────────────────────────────────────────────────────

def validate_env() -> bool:
    required = {
        "SUPABASE_URL":        os.getenv("SUPABASE_URL"),
        "SUPABASE_SERVICE_ROLE": os.getenv("SUPABASE_SERVICE_ROLE"),
        "OPENROUTER_API_KEY":  os.getenv("OPENROUTER_API_KEY"),
        "VT_API_KEY1":         os.getenv("VT_API_KEY1"),
        "MALWARE_BAZAAR_KEY":  os.getenv("MALWARE_BAZAAR_KEY"),
    }
    missing = [k for k, v in required.items() if not v]
    if missing:
        log.error("Variáveis de ambiente faltando:", ", ".join(missing))
        log.warn("Verifique seu arquivo .env e tente novamente.")
        return False
    return True

# ─── CLIENTES ─────────────────────────────────────────────────────────────────

def init_clients():
    supabase = create_client(
        os.getenv("SUPABASE_URL"),
        os.getenv("SUPABASE_SERVICE_ROLE")
    )
    ai = AsyncOpenAI(
        base_url="https://openrouter.ai/api/v1",
        api_key=os.getenv("OPENROUTER_API_KEY"),
    )
    return supabase, ai

# ─── HUNTER ───────────────────────────────────────────────────────────────────

class NpmProtectHunter:
    def __init__(self, supabase: Client, ai: AsyncOpenAI):
        self.supabase = supabase
        self.ai = ai
        self.vt_keys = [k for k in [os.getenv("VT_API_KEY1"), os.getenv("VT_API_KEY2")] if k]
        self.mb_key = os.getenv("MALWARE_BAZAAR_KEY")
        self.processed = 0
        self.failed = 0

    # ── MalwareBazaar ──

    async def fetch_hashes(self, limit: int = 50) -> list[str]:
        log.info(f"Sincronizando feed do MalwareBazaar (últimos {limit})...")
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    "https://mb-api.abuse.ch/api/v1/",
                    data={"query": "get_recent", "selector": str(limit)},
                    headers={"API-KEY": self.mb_key},
                    timeout=15.0
                )
                resp.raise_for_status()
                results = resp.json().get("data", [])
                hashes = [item["sha256_hash"] for item in results if "sha256_hash" in item]
                log.success(f"{len(hashes)} hashes obtidos.")
                return hashes
        except Exception as e:
            log.error("Falha ao obter feed do MalwareBazaar", str(e))
            return []

    # ── VirusTotal ──

    async def check_vt_exists(self, file_hash: str) -> bool:
        headers = {"x-apikey": self.vt_keys[0]}
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}",
                    headers=headers,
                    timeout=10.0
                )
                return resp.status_code == 200
        except:
            return False

    async def post_to_vt(self, file_hash: str, comment_text: str) -> bool:
        key = self.vt_keys[0] if self.vt_keys else None
        if not key:
            log.warn("Nenhuma VT key disponível, pulando publicação.")
            return False

        safe_text = comment_text[:4000].replace('"', "'").replace("\\", "/")
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"https://www.virustotal.com/api/v3/files/{file_hash}/comments",
                    headers={"x-apikey": key, "Content-Type": "application/json"},
                    json={"data": {"type": "comment", "attributes": {"text": safe_text}}},
                    timeout=20.0
                )
                if resp.status_code == 200:
                    log.success("Relatório publicado no VirusTotal.")
                    return True
                else:
                    log.warn(f"VT retornou {resp.status_code} — hash pode não estar indexado.")
                    return False
        except Exception as e:
            log.error("Falha ao publicar no VirusTotal", str(e))
            return False

    # ── IA ──

    async def generate_report(self, file_hash: str, report_id: int) -> str | None:
        prompt = (
            f"Você é um analista sênior da Vynex Labs (Mozart_Dev).\n"
            f"Produza um relatório técnico forense completo em Markdown para o malware com hash SHA-256:\n"
            f"`{file_hash}`\n\n"
            f"ID do Relatório: {report_id}\n\n"
            f"Estrutura obrigatória:\n"
            f"- Overview\n"
            f"- Análise Estática (tipo de arquivo, strings suspeitas, DLLs)\n"
            f"- Análise Dinâmica (comportamento, rede, persistência)\n"
            f"- Mapeamento MITRE ATT&CK\n"
            f"- Indicadores de Comprometimento (IOCs)\n"
            f"- Conclusão e Recomendações\n\n"
            f"Seja denso e técnico. Sem aspas duplas no texto."
        )
        try:
            resp = await self.ai.chat.completions.create(
                model="meta-llama/llama-3-70b-instruct",
                messages=[{"role": "user", "content": prompt}],
                max_tokens=2000,
            )
            return resp.choices[0].message.content.strip()
        except Exception as e:
            log.error("Falha na geração do relatório pela IA", str(e))
            return None

    # ── Supabase ──

    async def save_report(self, file_hash: str, report_id: int, content: str) -> bool:
        try:
            self.supabase.table("reports").insert({
                "hash": file_hash,
                "report_id": str(report_id),
                "content": content,
                "analyst": "Mozart_Dev"
            }).execute()
            log.success(f"Sincronizado com Supabase → ID {report_id}")
            return True
        except Exception as e:
            log.error("Falha ao salvar no Supabase", str(e))
            return False

    # ── Pipeline Principal ──

    async def process(self, file_hash: str):
        log.info(f"Analisando: {file_hash[:20]}...{file_hash[-8:]}")

        if not await self.check_vt_exists(file_hash):
            log.warn("Hash não indexado no VirusTotal. Pulando.")
            return

        log.success("Hash confirmado no VirusTotal.")
        report_id = random.randint(1000, 9999)

        analysis = await self.generate_report(file_hash, report_id)
        if not analysis:
            self.failed += 1
            return

        log.success("Relatório gerado pela IA.")

        vt_ok = await self.post_to_vt(file_hash, f"🛡️ NpmProtect Intel Report - ID {report_id}\n\n{analysis}")

        if vt_ok:
            saved = await self.save_report(file_hash, report_id, analysis)
            if saved:
                self.processed += 1
        else:
            log.warn("VT recusou — relatório não salvo.")
            self.failed += 1

# ─── MAIN ─────────────────────────────────────────────────────────────────────

async def main():
    print()
    print("  ███╗   ██╗██████╗ ███╗   ███╗██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗")
    print("  ████╗  ██║██╔══██╗████╗ ████║██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝")
    print("  ██╔██╗ ██║██████╔╝██╔████╔██║██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║   ")
    print("  ██║╚██╗██║██╔═══╝ ██║╚██╔╝██║██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║   ")
    print("  ██║ ╚████║██║     ██║ ╚═╝ ██║██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║   ")
    print("  ╚═╝  ╚═══╝╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   ")
    print()
    print("  🛡️  NpmProtect v7.0 | Vynex Labs | Mozart_Dev")
    print("  ─────────────────────────────────────────────")
    print()

    if not validate_env():
        sys.exit(1)

    supabase, ai = init_clients()
    hunter = NpmProtectHunter(supabase, ai)

    # Quantos malwares analisar por sessão
    batch_size = int(os.getenv("BATCH_SIZE", 5))
    cooldown   = int(os.getenv("COOLDOWN_SECONDS", 45))

    hashes = await hunter.fetch_hashes(limit=100)
    if not hashes:
        log.error("Nenhum hash disponível. Encerrando.")
        sys.exit(1)

    targets = random.sample(hashes, min(len(hashes), batch_size))
    log.info(f"Sessão iniciada → {len(targets)} alvos selecionados | Cooldown: {cooldown}s entre cada")
    print()

    for i, h in enumerate(targets, 1):
        print(f"  ── [{i}/{len(targets)}] ─────────────────────────────────")
        await hunter.process(h)
        if i < len(targets):
            log.info(f"Cooldown de {cooldown}s...")
            await asyncio.sleep(cooldown)

    print()
    print("  ─────────────────────────────────────────────")
    log.success(f"Sessão encerrada → ✅ {hunter.processed} processados | ❌ {hunter.failed} falhas")
    print()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print()
        log.warn("Interrompido pelo usuário.")
        sys.exit(0)
