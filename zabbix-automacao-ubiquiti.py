from pyzabbix import ZabbixAPI
from netmiko import ConnectHandler, NetMikoTimeoutException, NetMikoAuthenticationException
import logging
logging.basicConfig(filename='netmiko.log', level=logging.DEBUG)

# Configurações do Zabbix API
zabbix_server = "URL-Zabbix"
zabbix_username = "user"
zabbix_password = "password"

# Conexão com a API do Zabbix
zapi = ZabbixAPI(zabbix_server)
zapi.login(zabbix_username, zabbix_password)

# Obtém todos os hosts
hosts = zapi.host.get(output=['hostid', 'name'])

# Comando para verificar a configuração da porta SSH
command = 'cat /tmp/system.cfg'

failed_ips_file = 'failed_ips.txt'

# Arquivo para salvar os IPs dos dispositivos alterados
success_ips_file = 'success_ips.txt'

# Configuração de comandos para alterar a porta SSH
config_commands_255 = [
    #remove todas as configuracoes do arquivo system
    'sed -i "/sshd.port=22/d" /tmp/system.cfg',
    'sed -i "/sshd.port=255/d" /tmp/system.cfg',  
    'sed -i "/syslog.remote.status=disabled/d" /tmp/system.cfg',
    'sed -i "/syslog.remote.ip=172.16.180.4/d" /tmp/system.cfg',
    'sed -i "/syslog.remote.port=5555/d" /tmp/system.cfg',
    'sed -i "/syslog.remote.status=enabled/d" /tmp/system.cfg',
    #removendo as configuracoes do que esta rodando
    'sed -i "/sshd.port=22/d" /tmp/running.cfg', 
    'sed -i "/sshd.port=255/d" /tmp/running.cfg',  
    'sed -i "/syslog.remote.status=disabled/d" /tmp/running.cfg',
    'sed -i "/syslog.remote.ip=172.16.180.4/d" /tmp/running.cfg',
    'sed -i "/syslog.remote.port=5555/d" /tmp/running.cfg',
    'sed -i "/syslog.remote.status=enabled/d" /tmp/running.cfg',
    #seta as configuracao no arquivo system
    'echo "sshd.port=22" >> /tmp/system.cfg', 
    'echo "syslog.remote.ip=172.16.180.4" >> /tmp/system.cfg', 
    'echo "syslog.remote.port=5555" >> /tmp/system.cfg', 
    'echo "syslog.remote.status=enabled" >> /tmp/system.cfg', 
    #salvando e reiniciando
    'cfgmtd -w -p /etc/',                     
    'save',
    '/usr/etc/rc.d/rc.softrestart save'
]

config_commands_22 = [
    #remove todas as configuracoes do arquivo system 
    'sed -i "/syslog.remote.status=disabled/d" /tmp/system.cfg',
    'sed -i "/syslog.remote.ip=172.16.180.4/d" /tmp/system.cfg',
    'sed -i "/syslog.remote.port=5555/d" /tmp/system.cfg',
    'sed -i "/syslog.remote.status=enabled/d" /tmp/system.cfg',
    #removendo as configuracoes do que esta rodando
    'sed -i "/syslog.remote.status=disabled/d" /tmp/running.cfg',
    'sed -i "/syslog.remote.ip=172.16.180.4/d" /tmp/running.cfg',
    'sed -i "/syslog.remote.port=5555/d" /tmp/running.cfg',
    'sed -i "/syslog.remote.status=enabled/d" /tmp/running.cfg',
    #seta as configuracao no arquivo system
    'echo "syslog.remote.ip=172.16.180.4" >> /tmp/system.cfg', 
    'echo "syslog.remote.port=5555" >> /tmp/system.cfg', 
    'echo "syslog.remote.status=enabled" >> /tmp/system.cfg', 
    #salvando e reiniciando
    'cfgmtd -w -p /etc/',                     
    'save',
    '/usr/etc/rc.d/rc.softrestart save'
]

# Função para tentar conexão e reconfigurar a porta SSH se necessário
def configure_ssh_port(device, command_to_check):
    try:
        net_connect = ConnectHandler(**device)
        print(f"Conexão bem-sucedida no dispositivo {device['ip']} na porta {device['port']}")

        # Escolhe o conjunto de comandos com base na porta
        if device['port'] == 255:
            config_commands = config_commands_255
        else:  # Assume porta 22
            config_commands = config_commands_22

        for command in config_commands:
            output = net_connect.send_command(command)
            print(f"Saída do comando '{command}': {output}")

        # Escreve o IP do dispositivo no arquivo após a execução bem-sucedida dos comandos
        with open(success_ips_file, 'a') as file:
            file.write(f"{device['ip']}\n")

        net_connect.disconnect()
    except NetMikoAuthenticationException:
        print(f"Falha de autenticação no dispositivo {device['ip']}. Ignorando dispositivo.")
        with open(failed_ips_file, 'a') as file:
            file.write(f"Falha de autenticação: {device['ip']}\n")
    except NetMikoTimeoutException as e:
        if device['port'] == 22:
            print(f"Falha ao conectar no dispositivo {device['ip']} na porta 22. Tentando na porta 255...")
            with open(failed_ips_file, 'a') as file:
                file.write(f"Falha de conexão: {device['ip']} na porta {device['port']}\n")
            device['port'] = 255
            configure_ssh_port(device, command_to_check)  # Tente reconectar com a porta 255
        else:
            print(f"Falha ao conectar no dispositivo {device['ip']} na porta 255. Ignorando dispositivo.")
            with open(failed_ips_file, 'a') as file:
                file.write(f"Erro genérico: {device['ip']} - {e}\n")
    except Exception as e:
        print(f"Erro ao conectar ao dispositivo {device['ip']}: {e}")
        with open(failed_ips_file, 'a') as file:
            file.write(f"Erro genérico: {device['ip']} - {e}\n")


# Loop por todos os hosts e verifica o modelo
for host in hosts:
    hostid = host['hostid']
    items = zapi.item.get(
        output=['lastvalue'],
        hostids=hostid,
        search={"key_": "system.descr[sysDescr.0]"}
    )
    if items and "Linux" in items[0]['lastvalue']:
        interfaces = zapi.hostinterface.get(
            output=['ip'],
            hostids=hostid,
            sortfield='interfaceid'
        )
        if interfaces:
            loopback_ip = interfaces[0]['ip']
            device = {
                'device_type': 'ubiquiti_edge',
                'ip': loopback_ip,
                'username': 'user',
                'password': 'password',
                'port': 22,
                'timeout': 300  # Aumenta o tempo de leitura (valor em segundos)
            }
            configure_ssh_port(device, command)  # Primeira tentativa na porta 22

# Faz logout da API do Zabbix
zapi.user.logout()
