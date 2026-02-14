<div align="center">

<img src="https://img.shields.io/badge/NpmProtect-Intel-ff1a1a?style=for-the-badge&logo=npm&logoColor=white"/>

# 🛡️ NpmProtect

**We don't like malware, so we fight it automatically.**

*Indie open-source threat intelligence for the npm ecosystem.*

[![Live Dashboard](https://img.shields.io/badge/Dashboard-Live-00ff88?style=flat-square&logo=vercel&logoColor=black)](https://npmprotect.vercel.app)
[![PyPI](https://img.shields.io/badge/PyPI-npmprotect-3775A9?style=flat-square&logo=pypi&logoColor=white)](https://pypi.org/project/npmprotect)
[![License: MIT](https://img.shields.io/badge/License-MIT-red?style=flat-square)](LICENSE)
[![Python](https://img.shields.io/badge/Python-3.10+-blue?style=flat-square&logo=python&logoColor=white)](https://python.org)

</div>

---

## 🔍 O que é?

NpmProtect é um sistema automatizado de inteligência contra malware no ecossistema npm. O pipeline coleta hashes de amostras ativas, cruza com múltiplas fontes de threat intel, gera relatórios técnicos com IA e publica tudo em tempo real — de graça, sem conta, sem paywall.

---

## ⚙️ Stack

<div align="center">

| Camada | Tecnologia |
|--------|-----------|
| 🧠 **IA / Relatórios** | ![OpenRouter](https://img.shields.io/badge/OpenRouter-Llama_3_70B-purple?style=flat-square) |
| 🦠 **Feed de Malwares** | ![MalwareBazaar](https://img.shields.io/badge/MalwareBazaar-abuse.ch-orange?style=flat-square) |
| 🔬 **Análise Multi-engine** | ![VirusTotal](https://img.shields.io/badge/VirusTotal-Dual_Key-4285F4?style=flat-square&logo=virustotal&logoColor=white) |
| 🧪 **Sandbox Dinâmica** | ![Tria.ge](https://img.shields.io/badge/Tria.ge-Sandbox-yellow?style=flat-square) |
| ☁️ **Banco de Dados** | ![Supabase](https://img.shields.io/badge/Supabase-Realtime-3ECF8E?style=flat-square&logo=supabase&logoColor=white) |
| 🌐 **Dashboard** | ![Vercel](https://img.shields.io/badge/Vercel-Deployed-black?style=flat-square&logo=vercel&logoColor=white) |
| 🐍 **Backend** | ![Python](https://img.shields.io/badge/Python-asyncio-3776AB?style=flat-square&logo=python&logoColor=white) |
| 📦 **CLI** | ![PyPI](https://img.shields.io/badge/PyPI-npmprotect-3775A9?style=flat-square&logo=pypi&logoColor=white) |

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

## 📦 CLI — Instalação

```bash
pip install npmprotect
```

### Comandos disponíveis

```bash
npmprotect check <pacote>          # Verifica se um pacote npm é seguro
npmprotect check <pacote> --vt     # Verifica + análise VirusTotal
npmprotect latest --limit 10       # Lista últimos malwares detectados
npmprotect report <hash>           # Relatório completo de um hash SHA-256
npmprotect stats                   # Estatísticas da base de inteligência
```

### Exemplos reais

```bash
npmprotect check lodahs            # ⚠️ Typosquat de lodash — flagrado!
npmprotect check expresss --vt     # ⚠️ Typosquat de express — flagrado!
npmprotect check express --vt      # ✅ Legítimo, 69M downloads/semana
```

---

## 🚀 Rodando o Hunter localmente

O `main.py` é o pipeline de análise automatizado. Ele busca malwares, gera relatórios com IA e sincroniza com o Supabase.

### 1. Clone o repositório

```bash
git clone https://github.com/mozartdev-0/NpmProtect
cd NpmProtect
pip install -r requirements.txt
```

### 2. Configure o `.env`

Crie um arquivo `.env` na raiz com as seguintes variáveis:

```env
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_SERVICE_ROLE=eyJ...
OPENROUTER_API_KEY=sk-or-...
VT_API_KEY1=sua_chave_virustotal_1
VT_API_KEY2=sua_chave_virustotal_2       # opcional, dobra o rate limit
MALWARE_BAZAAR_KEY=sua_chave_bazaar
BATCH_SIZE=5                             # malwares por sessão (padrão: 5)
COOLDOWN_SECONDS=45                      # espera entre análises (padrão: 45)
```

### 3. Rode

```bash
python main.py
```

---

## 🔑 Como obter as chaves de API

### Supabase — `SUPABASE_URL` e `SUPABASE_SERVICE_ROLE`

1. Acesse [supabase.com](https://supabase.com) e crie uma conta gratuita
2. Crie um novo projeto
3. Vá em **Project Settings → API**
4. Copie:
   - **Project URL** → `SUPABASE_URL`
   - **service_role (secret)** → `SUPABASE_SERVICE_ROLE` *(nunca exponha essa chave publicamente)*
   - **anon public** → use essa no CLI (`SUPABASE_KEY`) — é segura pra expor

> A tabela `reports` precisa existir no Supabase com as colunas: `hash`, `report_id`, `content`, `analyst`, `created_at`

---

### VirusTotal — `VT_API_KEY1` / `VT_API_KEY2`

1. Acesse [virustotal.com](https://www.virustotal.com) e crie uma conta gratuita
2. Clique no seu avatar → **API Key**
3. Copie a chave e cole como `VT_API_KEY1`
4. Crie uma segunda conta para ter `VT_API_KEY2` e dobrar o rate limit

> O plano gratuito permite **4 requests/minuto**. Com 2 chaves, alterna automaticamente.

---

### OpenRouter — `OPENROUTER_API_KEY`

1. Acesse [openrouter.ai](https://openrouter.ai) e crie uma conta
2. Vá em **Keys → Create Key**
3. Copie a chave (`sk-or-...`) e cole como `OPENROUTER_API_KEY`

> O modelo usado é `meta-llama/llama-3-70b-instruct`. Tem créditos gratuitos ao criar conta.

---

### MalwareBazaar — `MALWARE_BAZAAR_KEY`

1. Acesse [bazaar.abuse.ch](https://bazaar.abuse.ch) e crie uma conta
2. Vá em **Account → API Key**
3. Copie a chave e cole como `MALWARE_BAZAAR_KEY`

> Totalmente gratuito. Sem limites agressivos.

---

## 📊 Dashboard

Acesse **[npmprotect.vercel.app](https://npmprotect.vercel.app)** para ver todos os relatórios em tempo real.

- 🔴 Listagem de hashes SHA-256 detectados
- 📄 Relatórios completos com análise estática, dinâmica e MITRE ATT&CK
- 🔍 Busca por hash ou conteúdo
- ⚡ Feed ao vivo via Supabase Realtime

---

## 🗺️ Roadmap

- [x] Pipeline de análise automatizado
- [x] Dashboard público em tempo real
- [x] Publicação de relatórios no VirusTotal
- [x] CLI global (`pip install npmprotect`)
- [x] Verificação real de pacotes npm + typosquatting detection
- [ ] Proteção ativa contra typosquatting no `npm install`
- [ ] Scoring de severidade por hash
- [ ] API pública REST
- [ ] Upload de arquivos para análise manual

---

## 📄 Licença

MIT — use, modifique, contribua.

---

<div align="center">

**Feito por [Mozart_Dev](https://github.com/mozartdev-0) · Vynex Labs**

*Fighting malware, one hash at a time.* 🛡️

</div>
