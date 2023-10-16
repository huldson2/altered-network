import tkinter as tk
from tkinter import messagebox
import subprocess
import winreg

def configurar_os():
    try:
        # Configurações da rede OS
        gateway = "192.168.88.1"
        dns_primario = "1.1.1.1"
        dns_secundario = "1.0.0.1"

        # Configurar o gateway IPv4
        subprocess.run(["netsh", "interface", "ipv4", "set", "address", "name='Conexão de Rede'", "source=static", f"addr={gateway}", "mask=255.255.255.0"])

        # Configurar os DNS primário e secundário
        subprocess.run(["netsh", "interface", "ipv4", "set", "dns", "name='Conexão de Rede'", "source=static", f"addr={dns_primario}", "register=primary"])
        subprocess.run(["netsh", "interface", "ipv4", "add", "dns", "name='Conexão de Rede'", f"addr={dns_secundario}", "index=2"])

        # Desativar o proxy e ativar a detecção automática de configurações
        set_proxy_settings(False, "", "")
        set_auto_detect_proxy(True)

        messagebox.showinfo("Configuração", "Configuração concluída para OS")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao configurar a rede OS: {str(e)}")

def configurar_iplan():
    try:
        # Configurações da rede IPLAN
        gateway = "10.30.79.2"
        dns_primario = "10.2.221.52"
        dns_secundario = "10.2.221.104"
        proxy_pac_url = "http://www.rio.rj.gov.br/proxy/remoto.pac"
        proxy_server = "http://proxy.rio.rj.gov.br:8080"

        # Configurar o gateway IPv4
        subprocess.run(["netsh", "interface", "ipv4", "set", "address", "name='Conexão de Rede'", "source=static", f"addr={gateway}", "mask=255.255.255.0"])

        # Configurar os DNS primário e secundário
        subprocess.run(["netsh", "interface", "ipv4", "set", "dns", "name='Conexão de Rede'", "source=static", f"addr={dns_primario}", "register=primary"])
        subprocess.run(["netsh", "interface", "ipv4", "add", "dns", "name='Conexão de Rede'", f"addr={dns_secundario}", "index=2"])

        # Ativar o proxy automático com a URL do script e desativar a detecção automática
        set_proxy_settings(True, proxy_pac_url, proxy_server)
        set_auto_detect_proxy(False)

        messagebox.showinfo("Configuração", "Configuração concluída para IPLAN")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao configurar a rede IPLAN: {str(e)}")

def set_proxy_settings(enable, pac_url, proxy_server):
    key = winreg.HKEY_CURRENT_USER
    subkey = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    
    with winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE) as regkey:
        winreg.SetValueEx(regkey, "ProxyEnable", 0, winreg.REG_DWORD, int(enable))
        winreg.SetValueEx(regkey, "AutoConfigURL", 0, winreg.REG_SZ, pac_url)
        winreg.SetValueEx(regkey, "ProxyServer", 0, winreg.REG_SZ, proxy_server)

def set_auto_detect_proxy(enable):
    key = winreg.HKEY_CURRENT_USER
    subkey = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
    
    with winreg.OpenKey(key, subkey, 0, winreg.KEY_WRITE) as regkey:
        winreg.SetValueEx(regkey, "AutoDetect", 0, winreg.REG_DWORD, int(enable))

def selecionar_configuracao(opcao):
    if opcao == "OS":
        configurar_os()
    elif opcao == "IPLAN":
        configurar_iplan()

root = tk.Tk()
root.title("Configuração de Rede")

configurar_os_button = tk.Button(root, text="Configurar OS", command=lambda: selecionar_configuracao("OS"))
configurar_iplan_button = tk.Button(root, text="Configurar IPLAN", command=lambda: selecionar_configuracao("IPLAN"))

configurar_os_button.pack()
configurar_iplan_button.pack()

root.mainloop()
