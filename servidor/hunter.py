import httpx

import asyncio

import os

import re

import random

import json

from datetime import datetime

from openai import AsyncOpenAI

from dotenv import load_dotenv

from supabase import create_client, Client


# Carrega variáveis do .env

load_dotenv()


# Configuração OpenRouter (IA)

ai_client = AsyncOpenAI(

    base_url="https://openrouter.ai/api/v1",

    api_key=os.getenv("OPENROUTER_API_KEY"),

)


# Configuração Supabase

SUPABASE_URL = os.getenv("SUPABASE_URL")

SUPABASE_KEY = os.getenv("SUPABASE_SERVICE_ROLE") # Sua Service Role aqui

supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)


class VynexLogger:

    @staticmethod

    def info(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔵 [INFO] {msg}")

    @staticmethod

    def success(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟢 [SUCCESS] {msg}")

    @staticmethod

    def warn(msg): print(f"[{datetime.now().strftime('%H:%M:%S')}] 🟡 [WARN] {msg}")

    @staticmethod

    def error(msg, detail=""): print(f"[{datetime.now().strftime('%H:%M:%S')}] 🔴 [ERROR] {msg} | {detail}")


class NpmProtectHunter:

    def __init__(self):

        # Chaves do VirusTotal para o Dual-Engine

        self.vt_keys = [k for k in [os.getenv("VT_API_KEY1"), os.getenv("VT_API_KEY2")] if k]

        self.current_key_idx = 0

        self.base_url_vt = "https://www.virustotal.com/api/v3"


    async def fetch_hashes(self):

        """Busca hashes estáveis no MalwareBazaar."""

        url = "https://bazaar.abuse.ch/export/txt/sha256/recent/"

        VynexLogger.info("Sincronizando feeds de malwares ativos...")

        try:

            async with httpx.AsyncClient(follow_redirects=True) as client:

                resp = await client.get(url, timeout=15.0)

                return list(set(re.findall(r'\b([a-fA-F0-9]{64})\b', resp.text)))

        except Exception as e:

            VynexLogger.error("Falha ao obter feed", str(e))

            return []


    async def check_vt_exists(self, file_hash):

        """Verifica se o hash existe no VT (evita 404)."""

        url = f"{self.base_url_vt}/files/{file_hash}"

        headers = {"x-apikey": self.vt_keys[self.current_key_idx]}

        async with httpx.AsyncClient() as client:

            try:

                resp = await client.get(url, headers=headers)

                return resp.status_code == 200

            except: return False


    async def post_to_vt(self, file_hash, comment_text):

        """Envia o comentário para o VirusTotal."""

        url = f"{self.base_url_vt}/files/{file_hash}/comments"

        safe_text = comment_text.replace('"', "'").replace('\\', '/')

        payload = {"data": {"type": "comment", "attributes": {"text": safe_text}}}

        headers = {"x-apikey": self.vt_keys[self.current_key_idx], "Content-Type": "application/json"}

       

        async with httpx.AsyncClient() as client:

            try:

                resp = await client.post(url, headers=headers, json=payload, timeout=20.0)

                if resp.status_code == 200:

                    VynexLogger.success(f"Publicado no VirusTotal!")

                    return True

                return False

            except Exception as e:

                VynexLogger.error("Erro no POST VT", str(e))

                return False


async def save_to_supabase(file_hash, report_id, content):

    """Sincroniza o relatório com a Vynex Cloud (Supabase)."""

    try:

        data = {

            "hash": file_hash,

            "report_id": str(report_id),

            "content": content,

            "analyst": "Mozart_Dev"

        }

        supabase.table("reports").insert(data).execute()

        VynexLogger.success("Dados sincronizados com o Banco de Dados (Realtime Ativo).")

    except Exception as e:

        VynexLogger.error("Erro ao salvar no Supabase", str(e))


async def main():

    hunter = NpmProtectHunter()

    VynexLogger.info("🚀 NpmProtect v6.0 | Vynex Cloud Edition Online")

   

    all_hashes = await hunter.fetch_hashes()

    if not all_hashes: return

   

    random.shuffle(all_hashes)

   

    for h in all_hashes:

        VynexLogger.info(f"Monitorando: {h}")

       

        if await hunter.check_vt_exists(h):

            VynexLogger.success("Alvo confirmado no VirusTotal.")

           

            # IA gera a Inteligência

            report_id = random.randint(1000, 9999)

            prompt = f"Analista Vynex Labs: Relatório técnico profundo para o malware {h}. Markdown denso, MITRE ATT&CK, sem aspas."

           

            try:

                ai_resp = await ai_client.chat.completions.create(

                    model="meta-llama/llama-3-70b-instruct",

                    messages=[{"role": "user", "content": prompt}]

                )

                analysis = ai_resp.choices[0].message.content.strip()

                VynexLogger.success("Inteligência Reforçada gerada.")


                # 1. Envia para o VirusTotal

                header = f"🛡️ NpmProtect Intel Report - ID {report_id}\n\n"

                if await hunter.post_to_vt(h, header + analysis):

                   

                    # 2. Sincroniza com Supabase (SÓ SE O VT ACEITAR)

                    await save_to_supabase(h, report_id, analysis)

                   

                    VynexLogger.info("Ciclo completo. Cooldown de 45s...")

                    await asyncio.sleep(45)

               

            except Exception as e:

                VynexLogger.error("Falha no processamento", str(e))

        else:

            VynexLogger.warn("Hash não indexado (404). Pulando...")


if __name__ == "__main__":

    asyncio.run(main()) 
