import httpx
import asyncio
import os
import random
from datetime import datetime
from openai import AsyncOpenAI
from supabase import create_client, Client

# --- CONFIGURAÇÃO DE LOGS VYNEX ---
class VynexLogger:
    @staticmethod
    def info(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔵 [INFO] {msg}")
    @staticmethod
    def success(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟢 [SUCCESS] {msg}")
    @staticmethod
    def error(msg, detail=""): print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔴 [ERROR] {msg} | {detail}")

# --- INICIALIZAÇÃO DE CLIENTES ---
# O GitHub Actions injeta essas variáveis automaticamente
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE")
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

ai_client = AsyncOpenAI(
    base_url="https://openrouter.ai/api/v1",
    api_key=os.getenv("OPENROUTER_API_KEY"),
)

class NpmProtectHunter:
    def __init__(self):
        self.vt_keys = [os.getenv("VT_API_KEY1"), os.getenv("VT_API_KEY2")]
        self.mb_key = os.getenv("MALWARE_BAZAAR_KEY")

    async def fetch_hashes(self):
        """Busca hashes recentes no MalwareBazaar (Fonte Global)"""
        VynexLogger.info("Sincronizando feeds de malwares...")
        url = "https://mb-api.abuse.ch/api/v1/"
        data = {'query': 'get_recent', 'selector': '50'}
        headers = {'API-KEY': self.mb_key}
        
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, data=data, headers=headers, timeout=15.0)
                if resp.status_code == 200:
                    results = resp.json().get('data', [])
                    return [item['sha256_hash'] for item in results if 'sha256_hash' in item]
        except Exception as e:
            VynexLogger.error("Falha ao obter feed", str(e))
        return []

    async def post_to_vt(self, file_hash, comment_text):
        """Publica a inteligência no VirusTotal"""
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}/comments"
        # Limpa o texto para o VirusTotal não recusar por caracteres especiais
        safe_text = comment_text[:4000].replace('"', "'") 
        payload = {"data": {"type": "comment", "attributes": {"text": safe_text}}}
        headers = {"x-apikey": self.vt_keys[0], "Content-Type": "application/json"}
        
        async with httpx.AsyncClient() as client:
            try:
                resp = await client.post(url, headers=headers, json=payload)
                return resp.status_code == 200
            except: return False

async def main():
    hunter = NpmProtectHunter()
    VynexLogger.info("🚀 NpmProtect v6.8 | GitHub Cloud Automation")
    
    hashes = await hunter.fetch_hashes()
    if not hashes: 
        VynexLogger.error("Sem hashes para processar.")
        return

    # Seleciona 3 malwares por execução (para não estourar limite de tempo/tokens)
    target_list = random.sample(hashes, min(len(hashes), 3))

    for h in target_list:
        VynexLogger.info(f"Analisando alvo: {h[:15]}...")
        report_id = random.randint(100000, 999999)
        
        prompt = f"Analista Vynex Labs (Mozart): Relatório técnico forense para {h}. Markdown denso, foco em MITRE ATT&CK."
        
        try:
            ai_resp = await ai_client.chat.completions.create(
                model="meta-llama/llama-3-70b-instruct",
                messages=[{"role": "user", "content": prompt}]
            )
            analysis = ai_resp.choices[0].message.content.strip()
            
            # 1. Envia para o VirusTotal
            await hunter.post_to_vt(h, analysis)
            
            # 2. Salva na Nuvem (Supabase)
            data = {
                "hash": h, 
                "report_id": str(report_id), 
                "content": analysis, 
                "analyst": "Mozart_Dev"
            }
            supabase.table("reports").insert(data).execute()
            VynexLogger.success(f"Inteligência sincronizada para ID: {report_id}")
            
            # Cooldown pequeno entre análises
            await asyncio.sleep(10)
            
        except Exception as e:
            VynexLogger.error(f"Erro no processamento do hash {h[:8]}", str(e))

if __name__ == "__main__":
    asyncio.run(main())
