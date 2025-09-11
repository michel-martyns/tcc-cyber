from sqlalchemy import create_engine, inspect

DB_USER = "postgres" 
DB_PASS = "63aUM6Tjh7"
DB_HOST = "tcc-cse-cic-ids.c3o0mem8emzt.us-east-2.rds.amazonaws.com" 
DB_PORT = "5432" 
DB_NAME = "tcc_cse_cic_ids"
TABLE_NAME = "network_flows"

engine = create_engine(f"postgresql+psycopg2://{DB_USER}:{DB_PASS}@{DB_HOST}:{DB_PORT}/{DB_NAME}")

try:
    with engine.connect() as connection:
        print("Conexão bem-sucedida!")
except Exception as e:
    print("Erro na conexão:", e)
