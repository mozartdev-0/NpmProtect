<div align="center">

<img src="https://img.shields.io/badge/NpmProtect-Intel-ff1a1a?style=for-the-badge&logo=npm&logoColor=white"/>

# 🛡️ NpmProtect

**We don't like malware, so we fight it automatically.**

*Indie open-source threat intelligence for the npm ecosystem.*

[![Live Dashboard](https://img.shields.io/badge/Dashboard-Live-00ff88?style=flat-square&logo=vercel&logoColor=black)](https://npmprotect.vercel.app)
[![License: MIT](https://img.shields.io/badge/License-MIT-red?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)

</div>

---

## 🔍 O que é?

NpmProtect é um sistema automatizado de inteligência contra malware no ecossistema npm. O pipeline coleta hashes de amostras ativas, cruza com múltiplas fontes de threat intel, gera relatórios técnicos detalhados com IA e os publica em tempo real — de graça, sem conta, sem paywall.

---

## ⚙️ Stack

<div align="center">

| Camada | Tecnologia |
|--------|-----------|
| 🧠 **IA / Relatórios** | ![OpenRouter](https://img.shields.io/badge/OpenRouter-Llama_3_70B-purple?style=flat-square) |
| 🦠 **Feed de Malwares** | ![MalwareBazaar](https://img.shields.io/badge/MalwareBazaar-abuse.ch-orange?style=flat-square) |
| 🔬 **Análise Multi-engine** | ![VirusTotal](https://img.shields.io/badge/VirusTotal-Dual_Key-4285F4?style=flat-square&logo=virustotal&logoColor=white) |
| ☁️ **Banco de Dados** | ![Supabase](https://img.shields.io/badge/Supabase-Realtime-3ECF8E?style=flat-square&logo=supabase&logoColor=white) |
| 🌐 **Dashboard** | ![Vercel](https://img.shields.io/badge/Vercel-Deployed-black?style=flat-square&logo=vercel&logoColor=white) |
| 🐍 **Backend** | ![Python](https://img.shields.io/badge/Python-asyncio-3776AB?style=flat-square&logo=python&logoColor=white) |

</div>

---

## 🔄 Como funciona

```
MalwareBazaar ──► fetch SHA-256 hashes (feed ativo)
      │
      ▼
VirusTotal ──► confirma existência do hash (dual-key engine)
      │
      ▼
Llama 3 70B (OpenRouter) ──► gera relatório técnico em Markdown
      │                        MITRE ATT&CK · Static · Dynamic · IOCs
      ▼
VirusTotal ──► publica relatório como comentário público
      │
      ▼
Supabase ──► sincroniza com a cloud (realtime)
      │
      ▼
npmprotect.vercel.app ──► dashboard público, sem login
```

---

## 📊 Dashboard

Acesse **[npmprotect.vercel.app](https://npmprotect.vercel.app)** para ver todos os relatórios em tempo real.

- 🔴 Listagem de hashes SHA-256 detectados
- 📄 Relatórios completos com análise estática, dinâmica e MITRE ATT&CK
- 🔍 Busca por hash ou conteúdo
- ⚡ Feed ao vivo via Supabase Realtime

---

## 🚀 Rodando localmente

```bash
git clone https://github.com/mozartdev-0/NpmProtect
cd NpmProtect
pip install -r requirements.txt
```

> ⚠️ CLI em desenvolvimento — por enquanto o sistema roda via `main.py` direto.

Configure o `.env`:

```env
OPENROUTER_API_KEY=sua_chave
SUPABASE_URL=sua_url
SUPABASE_SERVICE_ROLE=sua_service_role
VT_API_KEY1=chave_virustotal_1
VT_API_KEY2=chave_virustotal_2
```

```bash
python main.py
```

---

## 🗺️ Roadmap

- [x] Pipeline de análise automatizado
- [x] Dashboard público em tempo real
- [x] Publicação de relatórios no VirusTotal
- [ ] CLI — `npm install -g npmprotect`
- [ ] Proteção contra typosquatting
- [ ] Interceptação de pacotes maliciosos no `npm install`
- [ ] Scoring de severidade por hash

---

## 📄 Licença

MIT — use, modifique, contribua.

---

<div align="center">

**Feito por [Mozart_Dev](https://github.com/mozartdev-0) · Vynex Labs**

*Fighting malware, one hash at a time.* 🛡️

</div>
