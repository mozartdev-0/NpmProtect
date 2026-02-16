<div align="center">

<img src="https://raw.githubusercontent.com/mozartdev-0/NpmProtect/main/assets/logo.png" width="120" alt="NpmProtect Logo" />

# 🛡️ NpmProtect

**Threat Intelligence Engine para o ecossistema npm**

[![PyPI version](https://img.shields.io/pypi/v/npmprotect?color=red&style=flat-square)](https://pypi.org/project/npmprotect/)
[![Python](https://img.shields.io/badge/python-3.10%2B-red?style=flat-square)](https://python.org)
[![License](https://img.shields.io/badge/license-MIT-red?style=flat-square)](LICENSE)
[![Dashboard](https://img.shields.io/badge/dashboard-live-red?style=flat-square)](https://npmprotect.vercel.app)

*Detecta, analisa e cataloga malware no ecossistema npm em tempo real.*

[Dashboard](https://npmprotect.vercel.app) · [PyPI](https://pypi.org/project/npmprotect/) · [Reportar Bug](https://github.com/mozartdev-0/NpmProtect/issues)

</div>

---

## 📋 Sobre

O **NpmProtect** é um sistema completo de Threat Intelligence focado no ecossistema npm. Ele monitora feeds de malware em tempo real, gera relatórios técnicos profissionais com IA, publica análises no VirusTotal e notifica via Discord.

**Componentes:**
- 🖥️ **Dashboard Web** — Interface pública em tempo real com busca e filtros
- 🤖 **Hunter** — Engine que monitora feeds, analisa com IA e cataloga malware automaticamente
- 💻 **CLI (`np`)** — Ferramenta de linha de comando para verificar pacotes e consultar a base

---

## 🚀 Instalação da CLI

```bash
pip install npmprotect
```

```bash
np --help
```

---

## ⚙️ Configuração

Crie um arquivo `.env` no seu diretório home (`~/.env`) ou na raiz do projeto:

```env
# ─── Supabase ───────────────────────────────
SUPABASE_URL=https://xxxx.supabase.co
SUPABASE_KEY=sua_anon_key_publica
SUPABASE_SERVICE_ROLE=sua_service_role_key

# ─── VirusTotal ─────────────────────────────
VT_API_KEY1=sua_chave_vt
T_RIP_API_KEY=SUA API NO https://www.threat.rip/
# ─── OpenRouter (IA) ────────────────────────
OPENROUTER_API_KEY=sk-or-...

# ─── Discord (opcional) ─────────────────────
DISCORD_WEBHOOK=https://discord.com/api/webhooks/...
```

> **Nota:** A CLI procura o `.env` automaticamente em `~/`, `~/.npmprotect/`, `~/NpmProtect/` e no diretório atual.

---

## 💻 Comandos CLI

### `np check <pacote>`
Verifica se um pacote npm é seguro.

```bash
np check lodash
np check expresss          # detecta typosquatting
np check axios --vt        # inclui análise do VirusTotal
```

**Output:**
```
  ╔══════════════════════════════════════╗
  ║  🛡️  NpmProtect  ·  Vynex Labs        ║
  ╚══════════════════════════════════════╝

  PACOTE        lodash
  VERSÃO        4.17.21
  AUTOR         jdalton
  DOWNLOADS     25,847,392 / semana
  BASE          Nenhuma ameaça registrada. ✔
```

---

### `np report <sha256>`
Busca o relatório completo de um hash SHA-256.

```bash
np report 25411e3f056d4be6cee0033da6208f661c9566c50022d5be81dbcab13fe5c240
```

---

### `np latest`
Lista os últimos malwares detectados.

```bash
np latest
np latest --limit 20
```

**Output:**
```
  01. 25411e3f056d4be6...  [85/100 CRITICAL]  15/02/2026 13:19
  02. 4eeeb2ebc9d6cb31...  [75/100 HIGH]      15/02/2026 13:22
  03. 8ec809c41cba7fc6...  [10/100 LOW]       15/02/2026 13:30
```

---

### `np stats`
Estatísticas gerais da base de inteligência.

```bash
np stats
```

```
  Total         347
  Críticos      89
  Última        15/02/2026 13:30
  Dashboard     https://npmprotect.vercel.app
```

---

### `np analisar`
Valida as chaves do `.env` e inicia o hunter automaticamente.

```bash
np analisar           # valida e inicia
np analisar --force   # inicia mesmo com chaves inválidas
```

```
  VALIDANDO CHAVES

  › Verificando Supabase...
  ✔ Supabase SERVICE_ROLE    ✔
  › Verificando VirusTotal...
  ✔ VT_API_KEY1              ✔
  › Verificando OpenRouter...
  ✔ OPENROUTER_API_KEY       ✔
  ✔ DISCORD_WEBHOOK          ✔

  ✔ Ambiente validado! Iniciando hunter...
```

> O hunter é baixado automaticamente do GitHub se não encontrado localmente.

---

## 🤖 Hunter

O hunter é o coração do NpmProtect. Ele roda em loop contínuo:

1. Busca hashes de malware do **MalwareBazaar**
2. Verifica duplicatas no banco de dados
3. Confirma existência no **VirusTotal** e coleta metadados
4. Gera **relatório técnico profissional** com IA (Gemini Flash Lite)
5. Calcula **score de severidade** (0–100)
6. Publica comentário no **VirusTotal**
7. Salva no **Supabase** com Realtime
8. Notifica no **Discord** com embed colorido
9. Aguarda 45 segundos e repete

### Formato do Relatório

```markdown
# 🛡️ MALWARE ANALYSIS REPORT: NpmProtect Security Engine

Date: February 15, 2026
Analyst: Mozart_Dev (Analyst ID: 4821)
Security Level: Critical 🔴

## 1. Executive Summary
## 2. File Metadata      ← tabela com dados reais do VT
## 3. Detection Metrics  ← X / Y engines
## 4. Behavioral Analysis
## 5. MITRE ATT&CK Matrix
## 6. IOCs
## 7. Final Verdict & Recommendation
```

### Score de Severidade

| Score | Nível | Cor |
|-------|-------|-----|
| 0–39 | LOW | 🟢 |
| 40–59 | MEDIUM | 🟡 |
| 60–79 | HIGH | 🟠 |
| 80–100 | CRITICAL | 🔴 |

---

## 🌐 Dashboard

Acesse **[npmprotect.vercel.app](https://npmprotect.vercel.app)** para:

- Ver todos os malwares catalogados em tempo real
- Buscar por hash SHA-256
- Ler relatórios técnicos completos
- Filtrar por severidade
- Visualizar estatísticas globais

---

## 🔔 Notificações Discord

Configure o webhook e receba alertas assim:

```
🔴 Novo Malware Detectado — Severidade CRITICAL
🔑 SHA-256   25411e3f...
📊 Score     85/100 — CRITICAL
🆔 Report    ID #4821
📄 Preview   # 🛡️ MALWARE ANALYSIS REPORT...

🔍 Acesse npmprotect.vercel.app e pesquise por:
   25411e3f056d4be6cee0033da6208f661c9566c50022d5be81dbcab13fe5c240
```

---

## 🗄️ Banco de Dados

Schema da tabela `reports` no Supabase:

```sql
CREATE TABLE reports (
  id         SERIAL PRIMARY KEY,
  hash       TEXT UNIQUE NOT NULL,
  report_id  INTEGER,
  analyst    TEXT DEFAULT 'Mozart_Dev',
  content    TEXT,
  score      INTEGER DEFAULT 50,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Adicionar coluna score se já existir a tabela:
ALTER TABLE reports ADD COLUMN IF NOT EXISTS score INTEGER DEFAULT 50;
```

---

## 🔗 Integrações

| Serviço | Uso |
|---------|-----|
| [MalwareBazaar](https://bazaar.abuse.ch) | Feed de hashes de malware |
| [threat.rip](https://www.threat.rip/) | Se o virustotal não estiver disponivel |
| [VirusTotal](https://virustotal.com) | Metadados e publicação de análises |
| [OpenRouter](https://openrouter.ai) | IA para geração de relatórios (Gemini Flash Lite) |
| [Supabase](https://supabase.com) | Banco de dados com Realtime |
| [Discord](https://discord.com) | Notificações via Webhook |
| [Vercel](https://vercel.com) | Hospedagem do dashboard |

---

## 🛠️ Desenvolvimento

```bash
git clone https://github.com/mozartdev-0/NpmProtect
cd NpmProtect

# Instalar dependências
pip install -r requirements.txt

# Configurar .env
cp .env.example .env
# editar .env com suas chaves

# Rodar o hunter
python hunter.py

# Rodar a CLI localmente
cd cli
pip install -e .
np --help
```

---

## 📦 Publicar nova versão da CLI

```bash
cd cli
# Atualizar versão no setup.py
rm -rf dist/
python -m build
twine upload dist/*
```

---

## 📄 Licença

MIT © 2026 [Mozart_Dev](https://github.com/mozartdev-0) · Vynex Labs

---

<div align="center">

**[npmprotect.vercel.app](https://npmprotect.vercel.app)** · Feito com 🛡️ por Mozart_Dev

</div>
