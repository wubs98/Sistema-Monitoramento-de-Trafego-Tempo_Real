# Implementação de Sistema de Captura e Processamento de Pacotes

<p>Sistema de monitoramento de Carga em um servidor, o sistema processa o volume de tráfego de entrada e saída agrupado por cada cliente IP. Permite análise profunda dos protocolos usados na comunicação, exportando os dados capturados em arquivos csv</p>

# Requisitos

- Python (https://www.python.org/)
- Biblioteca python Scapy
- Biblioteca python Pandas
- Npcap (Para o Windows)

# Como Usar

<p>Baixe o repositório na máquina e mude a branch:</p>

```bash
git clone https://github.com/wubs98/Sistema-Monitoramento-de-Trafego-Tempo_Real
cd Sistema-Monitoramento-de-Trafego-Tempo_Real
git switch novo-main
```

<p>Algumas configurações são necessárias em ordem de iniciar a captura. Os campos IP_SERVER e INTERFACE no arquivo config.py da pasta backend devem ser alterados para o ip e interface da máquina, depois basta iniciar o arquivo 'main.py'</p> 

```bash
C:\Users\Usuario\Sistema-Análise-Tráfego-Tempo_Real> python main.py
```

<p>A captura se iniciará em janelas de tempo de 5 segundos. As informações sobre os pacotes como protocolos, clientes IP e volume de tráfego serão exportados em arquivos do formato csv dentro da pasta data, sendo possível carregá-los no Excel para o tratamendo dos dados</p>
