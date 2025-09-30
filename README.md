# Implementação de Sistema de Captura e Processamento de Pacotes

<p>Projeto para criação de um sistema de monitoramento de Carga em um servidor, o sistema deverá processar o volume de tráfego de entrada e saída agrupado por cada cliente IP, e exibi-los em uma interface front-end intuítiva com o uso de gráficos em barra dinâmico. Esta interface também deve permitir uma análise profunda dos protocolos usados na comunicação.</p>

# Como Usar

<p>Baixe o repositório na máquina e mude a branch:</p>

```bash
git clone https://github.com/wubs98/Sistema-Monitoramento-de-Trafego-Tempo_Real
cd Sistema-Monitoramento-de-Trafego-Tempo_Real
git switch novo-main
```

<p>Algumas configurações são necessárias em ordem de iniciar a captura. Os campos IP_SERVER e INTERFACE no arquivo config.py da pasta backend devem ser alterados para o ip e interface da máquina.</p> 