# AppSec Tools

![GitHub last commit](https://img.shields.io/github/last-commit/matheusbanhos/appsec-tools)
![GitHub issues](https://img.shields.io/github/issues/matheusbanhos/appsec-tools)
![GitHub stars](https://img.shields.io/github/stars/matheusbanhos/appsec-tools)
![GitHub license](https://img.shields.io/github/license/matheusbanhos/appsec-tools)

Uma coleção de ferramentas e scripts para auxiliar em tarefas de Segurança de Aplicações (AppSec).

## 🛠️ Ferramentas

### 1. Horusec JSON to Markdown Converter

Este script converte a saída JSON do Horusec em um relatório formatado em Markdown.

#### Características:

- Converte relatórios JSON do Horusec para Markdown legível
- Formata vulnerabilidades em uma tabela fácil de ler
- Fornece descrições detalhadas de cada vulnerabilidade
- Suporta ícones de severidade para fácil identificação visual
- Inclui informações de scan, como versão, status e timestamps

#### Uso:

```bash
python horusec_json2md.py input.json output.md [--color]
```

- `input.json`: Caminho para o arquivo JSON do Horusec
- `output.md`: Caminho para salvar o arquivo Markdown de saída
- `--color`: (Opcional) Habilita saída colorida no terminal

### 2. GitHub Actions Workflow para Horusec

Este workflow do GitHub Actions executa o Horusec SAST (Static Application Security Testing), gera um relatório e o salva como um artefato.

#### Características:

- Executa o Horusec em pushes e pull requests para a branch principal
- Gera um relatório Markdown a partir da saída JSON do Horusec
- Salva o relatório como um artefato do GitHub Actions
- Adiciona um resumo dos resultados ao sumário do GitHub Actions

#### Uso:

1. Copie o conteúdo do arquivo `horusec.yml` para `.github/workflows/horusec.yml` no seu repositório.
2. Personalize o workflow conforme necessário (por exemplo, alterando as branches de trigger).
3. Faça commit e push das alterações para seu repositório.

O workflow será executado automaticamente em pushes e pull requests para a branch principal.

### 3. Horusec Docker Linux Script

Este script bash (`horusec_docker_linux.sh`) automatiza a execução do Horusec em um ambiente Linux usando Docker.

#### Características:

- Configura parâmetros do Horusec, incluindo versão da imagem, níveis de severidade a serem ignorados, e diretórios a serem excluídos da análise
- Cria um diretório para armazenar os relatórios
- Executa o Horusec em um container Docker
- Gera um relatório JSON com os resultados da análise

#### Uso:

1. Certifique-se de que o Docker está instalado e em execução no seu sistema.
2. Dê permissão de execução ao script:
   ```
   chmod +x horusec_docker_linux.sh
   ```
3. Execute o script:
   ```
   ./horusec_docker_linux.sh
   ```

O script irá criar um diretório `reports` (se não existir) e gerar um arquivo `horusec_report.json` com os resultados da análise.

#### Configuração:

Você pode personalizar o script editando as seguintes variáveis no início do arquivo:

- `image`: Versão da imagem Docker do Horusec
- `severity_exception`: Níveis de severidade a serem ignorados
- `report_type`: Tipo de relatório (padrão: JSON)
- `report_directory`: Diretório para armazenar os relatórios
- `report_file`: Nome do arquivo de relatório
- `ignore`: Lista de diretórios e arquivos a serem ignorados na análise

## 🚀 Começando

Para usar estas ferramentas em seu projeto:

1. Clone este repositório:
   ```
   git clone https://github.com/matheusbanhos/appsec-tools.git
   ```
2. Instale as dependências necessárias:
   ```
   pip install -r requirements.txt
   ```
3. Execute os scripts conforme necessário, seguindo as instruções de uso acima.

## 🤝 Contribuindo

Contribuições são bem-vindas! Sinta-se à vontade para abrir issues ou enviar pull requests com melhorias ou novas ferramentas.

## 

**Matheus Banhos**

* GitHub: [@matheusbanhos](https://github.com/matheusbanhos)

---
