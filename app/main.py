import sys
import os
import pandas as pd

# Adiciona a raiz do projeto ao sys.path para permitir imports locais
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier

# Importa módulos das pastas locais
from utils.utils import ensure_dir, make_engine, read_sampled
from utils.eda import plot_class_balance, plot_top_ports, plot_protocols, plot_time_series_attacks
from utils.classificacao import train_and_evaluate
from utils.tendencias import fit_sarimax

# ======================
# Main Pipeline
# ======================

def main():
    # Diretório de saída
    out_dir = "./out"
    ensure_dir(out_dir)
    
    # Configuração do banco (ajuste para seu ambiente)
    CONFIG = {
        "db": {
            "host": "tcc-cse-cic-ids.c3o0mem8emzt.us-east-2.rds.amazonaws.com",
            "port": 5432,
            "database": "tcc_cse_cic_ids",
            "user": "postgres",
            "password": "63aUM6Tjh7",
            "sslmode": "require",
            "table_name": "network_flows_pipeline"
        },
        "label_col": "label",
        "ts_col": "timestamp",
        "negative_label": "BENIGN"
    }

    # Conexão com banco
    engine = make_engine(CONFIG)

    # Lê amostra de dados
    df = read_sampled(
        engine,
        table="network_flows",
        label_col=CONFIG["label_col"],
        ts_col=CONFIG["ts_col"],
        rows=50000,
        chunksize=10000,
        random_state=42,
        negative_label=CONFIG["negative_label"],
        positive_label="ATTACK"
    )

    # Remove colunas duplicadas
    df = df.loc[:, ~df.columns.duplicated()]

    # ---------------------
    # EDA
    # ---------------------
    plot_class_balance(df, CONFIG["label_col"], out_dir)
    plot_top_ports(df, out_dir)
    plot_protocols(df, out_dir)

    attacks_ts = plot_time_series_attacks(
        df,
        ts_col=CONFIG["ts_col"],
        label_col=CONFIG["label_col"],
        freq="H",
        out_dir=out_dir,
        negative_label=CONFIG["negative_label"]
    )

    # ---------------------
    # Modelagem – Classificação
    # ---------------------
    features = [c for c in df.columns if c not in [CONFIG["label_col"], CONFIG["ts_col"]]]
    X = df[features].select_dtypes(include="number").fillna(0)
    y = df[CONFIG["label_col"]]

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

    rf = RandomForestClassifier(n_estimators=100, random_state=42)
    train_and_evaluate(rf, X_train, y_train, X_test, y_test, out_dir, "random_forest")

    # ---------------------
    # Tendência – SARIMAX
    # ---------------------
    forecast_df = fit_sarimax(attacks_ts["attacks"], steps=48, out_dir=out_dir)
    forecast_df.to_csv(os.path.join(out_dir, "sarimax_forecast.csv"))

    # ---------------------
    # Salvar dataframe final no banco
    # ---------------------
    table_name = CONFIG["db"]["table_name"]
    df.to_sql(table_name, engine, if_exists='replace', index=False, method='multi', chunksize=10000)

    print("Pipeline finalizado com sucesso.")


if __name__ == "__main__":
    main()
