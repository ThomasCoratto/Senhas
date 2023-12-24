from cryptography.fernet import Fernet
import getpass
import os
import pandas as pd

def write_key():
    key = Fernet.generate_key()
    with open("key.key", "wb") as key_file:
        key_file.write(key)

def load_key():
    if not os.path.exists("key.key"):
        print("Arquivo de chave não encontrado. Gerando uma nova chave.")
        write_key()
    file = open("key.key", "rb")
    key = file.read()
    file.close()
    return key

def initialize():
    key = load_key()
    return Fernet(key)

def decrypt_password(fer, encrypted_password):
    try:
        decrypted_pass = fer.decrypt(encrypted_password.encode()).decode()
        return decrypted_pass
    except Exception as e:
        print(f"Erro ao descriptografar a senha: {e}")
        return None

def view():
    try:
        # Carrega os dados do arquivo Excel
        excel_path = r'C:\Users\maest\OneDrive\Área de Trabalho\Password\passwords.xlsx'
        if not os.path.exists(excel_path):
            print(f"Arquivo Excel '{excel_path}' não encontrado. Por favor, adicione senhas primeiro.")
            return

        df = pd.read_excel(excel_path)

        # Exibe as senhas descriptografadas
        for index, row in df.iterrows():
            user = row['Usuário']
            encrypted_pass = row['Senha']
            decrypted_pass = decrypt_password(fer, encrypted_pass)

            if decrypted_pass is not None:
                print(f"Usuário: {user} | Senha: {decrypted_pass}\n")

    except Exception as e:
        print(f"Ocorreu um erro ao ler as senhas: {e}")

def add():
    try:
        name = input('Nome da conta: ')
        pwd = getpass.getpass("Senha: ")

        if len(pwd) < 8:
            raise ValueError("A senha deve ter pelo menos 8 caracteres.")

        encrypted_pwd = fer.encrypt(pwd.encode())

        # Adiciona os novos dados ao DataFrame
        new_data = pd.DataFrame({'Usuário': [name], 'Senha': [encrypted_pwd.decode()]})

        # Carrega os dados existentes do arquivo Excel, se existirem
        excel_path = r'C:\Users\maest\OneDrive\Área de Trabalho\Password\passwords.xlsx'
        if os.path.exists(excel_path):
            df = pd.read_excel(excel_path)
            df = pd.concat([df, new_data], ignore_index=True)
        else:
            # Se o arquivo não existir, cria um DataFrame
            df = new_data

        # Salva o DataFrame atualizado como um arquivo Excel
        df.to_excel(excel_path, index=False)
        print(f'Dados adicionados e salvos em {excel_path}')

    except ValueError as ve:
        print(f"Erro: {ve}")
    except Exception as e:
        print(f"Ocorreu um erro ao adicionar uma senha: {e}")

def main():
    print("Bem-vindo ao Gerenciador de Senhas!")
    while True:
        mode = input("Deseja adicionar uma nova senha ou visualizar as existentes (view, add)? Pressione Q para sair ").lower()
        if mode == "q":
            break

        if mode == "view":
            view()
        elif mode == "add":
            add()
        else:
            print("Modo inválido.")
            continue

if __name__ == "__main__":
    fer = initialize()
    main()
