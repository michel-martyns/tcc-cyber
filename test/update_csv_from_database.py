import os
import re
import pandas as pd
from sqlalchemy import create_engine, inspect


# Configuração de conexão PostgreSQL
DB_USER = "USER" # Nome do úsuario
DB_PASS = "PASSWORD" # Senha de acesso ao banco
DB_HOST = "HOST" # Host de acesso ap banco
DB_PORT = "PORT" # Porta de acesso
DB_NAME = "DATABASE_NAME" # Nome do banco de dados
TABLE_NAME = "network_flows" # Nome da tabela que irá ser populada

engine = create_engine(f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

# Pasta onde estão os CSVs
DATA_DIR = r'caminho-do-arquivo' # Caminho que o arquivo a ser salvo no banco está salvo

# Função para limpar nomes de colunas
def clean_column(col):
    col = col.strip().lower()
    col = re.sub(r'[^a-z0-9_]', '_', col)
    col = re.sub(r'_+', '_', col)
    col = col.strip('_')
    return col

# Obtém colunas existentes na tabela
def get_existing_columns(table_name, engine):
    inspector = inspect(engine)
    return [col['name'] for col in inspector.get_columns(table_name)]

def process_file(file_path, existing_columns):
    try:
        file_name = os.path.basename(file_path)
        print(f"Processando {file_name}...")

        # Lê o CSV
        df = pd.read_csv(file_path, low_memory=False)

        # Normaliza nomes das colunas
        df.columns = [clean_column(c) for c in df.columns]

        # Mantém apenas colunas que existem na tabela
        cols_to_keep = [c for c in df.columns if c in existing_columns]
        df = df[cols_to_keep]

        # Adiciona coluna 'source_file' se existir na tabela
        if 'source_file' in existing_columns:
            df['source_file'] = file_name

        # Converte timestamp se existir
        if "timestamp" in df.columns:
            df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce", dayfirst=True)

        # Insere no banco em chunks
        df.to_sql(TABLE_NAME, engine, if_exists="append", index=False, chunksize=10000) 

        print(f"{file_name} inserido com sucesso")

    except Exception as e:
        print(f"Erro ao processar {file_name}: {e}")

def main():
    existing_columns = get_existing_columns(TABLE_NAME, engine)
    for file_name in sorted(os.listdir(DATA_DIR)):
        if file_name.endswith(".csv"):
            process_file(os.path.join(DATA_DIR, file_name), existing_columns)

if __name__ == "__main__":
    main()
