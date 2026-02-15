<div align="center">

<img src="https://img.shields.io/badge/-%F0%9F%9B%A1%EF%B8%8F%20NpmProtect%20Intel-ff1a1a?style=for-the-badge" />

<h1>NpmProtect</h1>

<p><strong>We don't like malware. So we fight it — automatically.</strong></p>
<p><em>Indie open-source threat intelligence for the npm ecosystem.</em></p>

<br/>

[![Dashboard](https://img.shields.io/badge/🌐_Dashboard-Live-00ff88?style=for-the-badge&logoColor=black)](https://npmprotect.vercel.app)
[![PyPI](https://img.shields.io/badge/🐍_PyPI-npmprotect-3775A9?style=for-the-badge)](https://pypi.org/project/npmprotect)
[![npm](https://img.shields.io/badge/📦_npm-@mozartdev0/npmprotect-cc3534?style=for-the-badge)](https://www.npmjs.com/package/@mozartdev0/npmprotect)
[![GitHub](https://img.shields.io/badge/⭐_GitHub-NpmProtect-181717?style=for-the-badge&logo=github)](https://github.com/mozartdev-0/NpmProtect)
[![License](https://img.shields.io/badge/📄_License-MIT-red?style=for-the-badge)](LICENSE)

<br/>

```
  ███╗   ██╗██████╗ ███╗   ███╗██████╗ ██████╗  ██████╗ ████████╗███████╗ ██████╗████████╗
  ████╗  ██║██╔══██╗████╗ ████║██╔══██╗██╔══██╗██╔═══██╗╚══██╔══╝██╔════╝██╔════╝╚══██╔══╝
  ██╔██╗ ██║██████╔╝██╔████╔██║██████╔╝██████╔╝██║   ██║   ██║   █████╗  ██║        ██║   
  ██║╚██╗██║██╔═══╝ ██║╚██╔╝██║██╔═══╝ ██╔══██╗██║   ██║   ██║   ██╔══╝  ██║        ██║   
  ██║ ╚████║██║     ██║ ╚═╝ ██║██║     ██║  ██║╚██████╔╝   ██║   ███████╗╚██████╗   ██║   
  ╚═╝  ╚═══╝╚═╝     ╚═╝     ╚═╝╚═╝     ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝ ╚═════╝   ╚═╝   
```

</div>

---

## 🔍 O que é?

NpmProtect é um sistema **automatizado de inteligência contra malware** no ecossistema npm. O pipeline coleta hashes de amostras ativas, cruza com múltiplas fontes de threat intel, gera relatórios técnicos com IA e publica tudo em tempo real — **de graça, sem conta, sem paywall.**

> Feito por um dev de 10 anos. Sério. 🔥

---

## ⚙️ Stack

<div align="center">

| Camada | Tecnologia |
|--------|-----------|
| 🧠 **IA / Relatórios** | ![OpenRouter](https://img.shields.io/badge/OpenRouter-Llama_3_70B-7c3aed?style=flat-square) |
| 🦠 **Feed de Malwares** | ![MalwareBazaar](https://img.shields.io/badge/MalwareBazaar-abuse.ch-ea580c?style=flat-square) |
| 🔬 **Análise Multi-engine** | ![VirusTotal](https://img.shields.io/badge/VirusTotal-Dual_Key-4285F4?style=flat-square&logo=virustotal&logoColor=white) |
| ☁️ **Banco de Dados** | ![Supabase](https://img.shields.io/badge/Supabase-Realtime-3ECF8E?style=flat-square&logo=supabase&logoColor=white) |
| 🌐 **Dashboard** | ![Vercel](https://img.shields.io/badge/Vercel-Deployed-000000?style=flat-square&logo=vercel&logoColor=white) |
| 🐍 **Backend / Hunter** | ![Python](https://img.shields.io/badge/Python-asyncio-3776AB?style=flat-square&logo=python&logoColor=white) |
| 📦 **CLI Python** | ![PyPI](https://img.shields.io/badge/PyPI-npmprotect-3775A9?style=flat-square&logo=pypi&logoColor=white) |
| 🟨 **SDK JavaScript** | ![npm](https://img.shields.io/badge/npm-@mozartdev0/npmprotect-cc3534?style=flat-square&logo=npm&logoColor=white) |

</div>

---

## 🔄 Pipeline de Análise

```
  ┌─────────────────┐
  │  MalwareBazaar  │  ← Feed de hashes SHA-256 ativos
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │   VirusTotal    │  ← Confirma existência (dual-key engine)
  └────────┬────────┘
           │
           ▼
  ┌─────────────────────────────────┐
  │  Llama 3 70B via OpenRouter     │  ← Gera relatório técnico
  │  MITRE ATT&CK · IOCs · Static  │
  └────────┬────────────────────────┘
           │
           ▼
  ┌─────────────────┐
  │   VirusTotal    │  ← Publica relatório como comentário público
  └────────┬────────┘
           │
           ▼
  ┌─────────────────┐
  │    Supabase     │  ← Sincroniza em tempo real
  └────────┬────────┘
           │
           ▼
  ┌──────────────────────────┐
  │  npmprotect.vercel.app   │  ← Dashboard público, sem login
  └──────────────────────────┘
```

---

## 🐍 CLI Python

```bash
pip install npmprotect
```

### Comandos

```bash
npmprotect check <pacote>          # 🔍 Verifica se um pacote npm é seguro
npmprotect check <pacote> --vt     # 🔬 Verifica + análise VirusTotal
npmprotect latest --limit 10       # 🦠 Últimos malwares detectados
npmprotect report <hash>           # 📄 Relatório completo por SHA-256
npmprotect stats                   # 📊 Estatísticas da base
```

### Exemplos reais

```bash
$ npmprotect check lodahs
  ⚠️  Nome similar a pacotes populares: lodash
  ⚠️  28 downloads/semana — pacote pouco conhecido!

$ npmprotect check expresss --vt
  ⚠️  Typosquat de: express
  ⚠️  Descrição: "temp test" — suspeito!

$ npmprotect check express --vt
  ✅ express — 69,722,421 downloads/semana
  ✅ VirusTotal: 0/97 engines — limpo.
```

---

## 🟨 SDK JavaScript

```bash
npm install @mozartdev0/npmprotect
```

Integre threat intelligence do NpmProtect no seu site ou app — **sem config, sem API key, zero dependências.**

```javascript
const { NpmProtect } = require('@mozartdev0/npmprotect')

const np = new NpmProtect()

// Últimos malwares detectados
const latest = await np.latest(10)

// Verificar pacote
const results = await np.check('lodash')

// Relatório completo
const report = await np.report('abc123...')

// Estatísticas
const stats = await np.stats()
// { total: 42, lastDetection: '2026-02-14T...', dashboard: 'https://npmprotect.vercel.app' }

// Info do pacote no npm
const info = await np.npmInfo('express')
// { exists: true, version: '5.2.1', downloads: 69722421, ... }
```

---

## 🚀 Rodando o Hunter localmente

### 1. Clone

```bash
git clone https://github.com/mozartdev-0/NpmProtect
cd NpmProtect
pip install -r requirements.txt
```

### 2. Configure o `.env`

```env
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_SERVICE_ROLE=eyJ...
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
OPENROUTER_API_KEY=sk-or-...
VT_API_KEY1=sua_chave_vt_1

VT_API_KEY2=sua_chave_vt_2        # opcional — dobra o rate limit
MALWARE_BAZAAR_KEY=sua_chave
BATCH_SIZE=5                      # malwares por sessão (padrão: 5)
COOLDOWN_SECONDS=45               # espera entre análises (padrão: 45)
```

### 3. Rode

```bash
python servidor/hunter.py
```

---

## 🔑 Como obter as chaves de API

<details>
<summary><b>🟢 Supabase — SUPABASE_URL e SUPABASE_SERVICE_ROLE</b></summary>

1. Acesse [supabase.com](https://supabase.com) e crie uma conta gratuita
2. Crie um novo projeto
3. Vá em **Project Settings → API**
4. Copie:
   - **Project URL** → `SUPABASE_URL`
   - **service_role (secret)** → `SUPABASE_SERVICE_ROLE` ⚠️ *nunca exponha publicamente*
   - **anon public** → use no CLI como `SUPABASE_KEY` — segura pra expor

> A tabela `reports` precisa existir com as colunas: `hash`, `report_id`, `content`, `analyst`, `created_at`

</details>

<details>
<summary><b>🔵 VirusTotal — VT_API_KEY1 / VT_API_KEY2</b></summary>

1. Acesse [virustotal.com](https://www.virustotal.com) e crie uma conta gratuita
2. Clique no seu avatar → **API Key**
3. Cole como `VT_API_KEY1`
4. Crie uma segunda conta para `VT_API_KEY2` e dobrar o rate limit

> Plano gratuito: **4 requests/minuto**. Com 2 chaves o hunter alterna automaticamente.

</details>

<details>
<summary><b>🟣 OpenRouter — OPENROUTER_API_KEY</b></summary>

1. Acesse [openrouter.ai](https://openrouter.ai) e crie uma conta
2. Vá em **Keys → Create Key**
3. Cole como `OPENROUTER_API_KEY` (`sk-or-...`)

> Modelo usado: `google/gemini-2.0-flash-lite-001`. Tem créditos gratuitos ao criar conta.

</details>

<details>
<summary><b>🟠 MalwareBazaar — MALWARE_BAZAAR_KEY</b></summary>

1. Acesse [bazaar.abuse.ch](https://bazaar.abuse.ch) e crie uma conta
2. Vá em **Account → API Key**
3. Cole como `MALWARE_BAZAAR_KEY`

> Totalmente gratuito. Sem limites agressivos.

</details>

---

## 📊 Dashboard ao vivo

**[npmprotect.vercel.app](https://npmprotect.vercel.app)**

- 🔴 Hashes SHA-256 detectados em tempo real
- 📄 Relatórios com MITRE ATT&CK, análise estática e dinâmica
- 🔍 Busca por hash ou conteúdo
- ⚡ Feed ao vivo via Supabase Realtime
- 🌍 Público — sem login, sem conta

---

## 🗺️ Roadmap

- [x] 🔄 Pipeline de análise automatizado
- [x] 🌐 Dashboard público em tempo real
- [x] 📝 Publicação de relatórios no VirusTotal
- [x] 🐍 CLI Python global (`pip install npmprotect`)
- [x] 🟨 SDK JavaScript (`npm install @mozartdev0/npmprotect`)
- [x] 🔍 Verificação real de pacotes + typosquatting detection
- [ ] 🛡️ Proteção ativa no `npm install`
- [ ] 📈 Scoring de severidade por hash
- [ ] 🔌 API pública REST
- [ ] 📤 Upload de arquivos para análise manual

---

## 📄 Licença

MIT — use, modifique, contribua.

---

<div align="center">

**Feito por [Mozart_Dev](https://github.com/mozartdev-0) · Vynex Labs**

*Fighting malware, one hash at a time.* 🛡️

<br/>

[![Dashboard](https://img.shields.io/badge/🌐-npmprotect.vercel.app-ff1a1a?style=for-the-badge)](https://npmprotect.vercel.app)

</div>
