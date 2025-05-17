# Scanner WordPress

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green.svg)](https://flask.palletsprojects.com/)

Uma ferramenta abrangente de análise de sites WordPress que examina temas, plugins, vulnerabilidades e muito mais. Esta ferramenta oferece tanto uma interface de linha de comando quanto uma interface web para fácil utilização.

## Índice

- [Funcionalidades](#funcionalidades)
- [Instalação](#instalação)
  - [Pré-requisitos](#pré-requisitos)
  - [Configuração](#configuração)
- [Uso](#uso)
  - [Interface de Linha de Comando](#interface-de-linha-de-comando)
  - [Interface Web](#interface-web)
- [Estrutura do Projeto](#estrutura-do-projeto)
- [Exemplo de Saída](#exemplo-de-saída)
- [Dependências](#dependências)
- [Limitações](#limitações)
- [Solução de Problemas](#solução-de-problemas)
- [Contribuindo](#contribuindo)
- [Autores](#autores)
- [Licença](#licença)
- [Agradecimentos](#agradecimentos)

## Funcionalidades

- **Detecção de WordPress**: Detecta automaticamente se um site está executando WordPress
- **Detecção de Tema**: Identifica o tema WordPress ativo
- **Detecção de Plugins**: Lista os plugins instalados e seus status (ativo/inativo)
- **Verificação de Vulnerabilidades**: Verifica vulnerabilidades comuns no core do WordPress e plugins
- **Melhorias de Segurança**: Sugere melhorias de segurança para o site WordPress
- **Informações de Hospedagem**: Fornece detalhes sobre o ambiente de hospedagem
- **Informações de Zona DNS**: Lista registros DNS para o domínio
- **Detecção de WAF**: Identifica se o site está protegido por um Firewall de Aplicação Web
- **Verificação SSL/TLS**: Analisa a segurança da conexão HTTPS e implementação de HSTS
- **Detecção de Modo de Depuração**: Verifica se o modo de depuração do WordPress está ativado
- **Verificação de Enumeração de Usuários**: Detecta vulnerabilidades que permitem listar usuários do site
- **Verificação da Versão do WordPress**: Verifica se a versão do WordPress é vulnerável
- **Verificação de Diretórios Listáveis**: Verifica se diretórios comuns (uploads, plugins, themes) estão listáveis
- **Detecção de Arquivos Sensíveis**: Detecta arquivos sensíveis expostos (.env, wp-config.php~, debug.log, etc)
- **Verificação de readme.html e license.txt**: Verifica a presença e conteúdo destes arquivos
- **Análise de Cabeçalhos de Segurança HTTP**: Identifica cabeçalhos de segurança ausentes (HSTS, CSP, X-Frame-Options)
- **Detecção de Execução de PHP**: Detecta se é possível executar PHP no diretório de uploads
- **Verificação de Proteção de Login**: Verifica se o login possui 2FA ou CAPTCHA
- **Verificação de Atualizações Automáticas**: Verifica se as atualizações automáticas estão habilitadas
- **Detecção de Plugins/Temas Piratas**: Verifica se o site utiliza plugins ou temas piratas (nulled)
- **Análise de Sitemap e Robots.txt**: Analisa estes arquivos para identificar exposições indesejadas
- **Análise de Versões JS/CSS**: Lista e analisa JS e CSS com query strings contendo versões

## Instalação

### Pré-requisitos

- Python 3.6+
- pip (gerenciador de pacotes Python)
- Git (opcional, para clonar o repositório)

### Configuração

1. Clone este repositório ou baixe o código-fonte:

```bash
git clone https://github.com/linehostcloud/linehostwpscan.git
cd wpscan
```

2. (Opcional) Crie e ative um ambiente virtual:

```bash
# Criar ambiente virtual
python -m venv .venv

# Ativar ambiente virtual no Windows
.venv\Scripts\activate

# Ativar ambiente virtual no Linux/Mac
source .venv/bin/activate
```

3. Instale as dependências necessárias:

```bash
pip install -r requirements.txt
```

Ou instale as dependências manualmente:

```bash
pip install requests>=2.25.0 beautifulsoup4>=4.9.3 dnspython>=2.1.0 python-whois>=0.7.3 flask>=2.0.0 colorama>=0.4.4
```

## Uso

### Interface de Linha de Comando

Você pode usar o Scanner WordPress diretamente da linha de comando:

```bash
# Modo interativo
python wpscan.py -i

# Analisar uma URL específica
python wpscan.py -u https://exemplo.com

# Salvar resultados em um arquivo
python wpscan.py -u https://exemplo.com -o resultados.json

# Mostrar ajuda
python wpscan.py -h
```

### Interface Web

Para iniciar a interface web:

```bash
python app.py
```

Em seguida, abra seu navegador e acesse `http://127.0.0.1:5000/`

A interface web permite:
1. Inserir a URL de um site WordPress
2. Visualizar os resultados da análise em um formato amigável
3. Salvar ou imprimir os resultados

## Estrutura do Projeto

```
wpscan/
├── app.py                 # Aplicação Flask para a interface web
├── wpscan.py              # Script principal do scanner
├── requirements.txt       # Dependências do projeto
├── README.md              # Documentação
├── static/                # Arquivos estáticos para a interface web
│   └── assets/
│       ├── css/           # Folhas de estilo
│       └── img/           # Imagens
├── templates/             # Templates HTML para a interface web
│   ├── index.html         # Página inicial
│   └── results.html       # Página de resultados
└── resultados/            # Diretório onde os resultados são salvos
```

## Exemplo de Saída

O scanner fornece informações detalhadas sobre o site WordPress, incluindo:

- Versão do WordPress e verificação de vulnerabilidades
- Tema ativo
- Plugins instalados
- Vulnerabilidades potenciais
- Sugestões de melhoria de segurança
- Informações de hospedagem (IP, servidor, registrador, etc.)
- Registros de zona DNS
- Status de segurança SSL/TLS
- Detecção de Firewall de Aplicação Web (WAF)
- Usuários expostos (se detectados)
- Status do modo de depuração
- Proteção de login (2FA/CAPTCHA)
- Status de atualizações automáticas
- Diretórios com listagem habilitada
- Arquivos sensíveis expostos
- Cabeçalhos de segurança HTTP ausentes
- Detecção de execução de PHP em uploads
- Detecção de plugins/temas piratas (nulled)
- Análise de sitemap.xml e robots.txt
- Arquivos JS/CSS com informações de versão

## Dependências

- **requests**: Para fazer requisições HTTP
- **beautifulsoup4**: Para análise de HTML
- **dnspython**: Para consultas DNS
- **python-whois**: Para informações WHOIS
- **flask**: Para a interface web
- **colorama**: Para saída colorida no terminal

## Solução de Problemas

### Problemas Comuns

1. **Erro de conexão ao site**
   - Verifique se a URL está correta e acessível
   - Confirme que o site não está bloqueando requisições do seu IP
   - Tente usar um proxy ou VPN se o site estiver bloqueando seu acesso

2. **Falha na detecção do WordPress**
   - Confirme que o site realmente usa WordPress
   - Alguns sites ocultam que estão usando WordPress por motivos de segurança
   - Tente usar a opção `-f` para forçar a análise mesmo que o WordPress não seja detectado

3. **Dependências não encontradas**
   - Execute `pip install -r requirements.txt` novamente
   - Verifique se você está usando Python 3.6+
   - Em alguns sistemas, pode ser necessário usar `pip3` em vez de `pip`

4. **Permissão negada ao salvar resultados**
   - Verifique se você tem permissão de escrita no diretório
   - Execute o script com privilégios de administrador se necessário

### Logs de Erro

Se você encontrar erros, verifique o console para mensagens detalhadas. Para obter logs mais detalhados, execute:

```bash
# Para a interface de linha de comando
python wpscan.py -u https://exemplo.com -v

# Para a interface web (modo debug)
export FLASK_ENV=development
python app.py
```

## Limitações

- A detecção de vulnerabilidades é simplificada e não deve ser considerada como uma auditoria de segurança completa
- Algumas informações podem não estar disponíveis dependendo da configuração do site
- O scanner respeita o robots.txt e pode não funcionar em sites que bloqueiam escaneamento automatizado

## Licença

Este projeto é de código aberto e disponível sob a Licença MIT.

## Contribuindo

Contribuições são bem-vindas! Siga estas etapas para contribuir:

1. Faça um fork do projeto
2. Crie uma branch para sua feature (`git checkout -b feature/nova-funcionalidade`)
3. Implemente suas mudanças
4. Adicione testes para suas mudanças, se aplicável
5. Execute os testes para garantir que tudo está funcionando
6. Faça commit das suas alterações (`git commit -m 'Adiciona nova funcionalidade'`)
7. Faça push para a branch (`git push origin feature/nova-funcionalidade`)
8. Abra um Pull Request

### Diretrizes para Contribuição

- Siga o estilo de código existente
- Mantenha o código limpo e bem documentado
- Adicione comentários quando necessário
- Atualize a documentação se você alterar funcionalidades
- Respeite o Código de Conduta em todas as interações

## Autores

- **LineHost Cloud** - *Trabalho inicial* - [LineHost](https://github.com/linehost)

Veja também a lista de [contribuidores](https://github.com/linehost/wpscan/contributors) que participaram deste projeto.

## Agradecimentos

- Agradecemos a todos que contribuíram com ideias, sugestões e código
- Inspirado por ferramentas como WPScan, Sucuri e outros scanners de segurança WordPress
- Obrigado à comunidade de segurança WordPress por compartilhar conhecimento e melhores práticas
