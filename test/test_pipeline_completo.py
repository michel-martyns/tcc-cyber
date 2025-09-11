"""
Pipeline completo para análise do CICIDS 2018 armazenado em PostgreSQL (RDS):
- Conecta no RDS e lê dados em chunks
- EDA resumida com gráficos
- Engenharia de features + balanceamento
- Modelo de classificação para tráfego malicioso vs benigno
- Modelo de tendência de ataques por tempo
- Gera artefatos: gráficos em PNG e relatórios em CSV/JSON

Como usar
1) Ajuste a seção CONFIG.
2) Garanta as libs instaladas.
3) Rode: python cicids2018_pipeline.py

Requisitos
pip install pandas numpy sqlalchemy psycopg2-binary scikit-learn imbalanced-learn matplotlib statsmodels pyyaml

Observações
- O script é robusto para tabelas grandes via leitura em chunks.
- Por padrão, faz amostra estratificada para acelerar iterações.
- A coluna alvo esperada é "Label". Valores típicos: "BENIGN" para normal e demais rótulos como ataques.
"""

import os
import json
import math
import yaml
from datetime import datetime
from typing import List, Tuple, Optional

import numpy as np
import pandas as pd
from sqlalchemy import create_engine, text
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.compose import ColumnTransformer
from sklearn.pipeline import Pipeline
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
import matplotlib.pyplot as plt
from statsmodels.tsa.statespace.sarimax import SARIMAX

# =====================
# CONFIG
# =====================
CONFIG = {
    "db": {
        "host": "tcc-cse-cic-ids.c3o0mem8emzt.us-east-2.rds.amazonaws.com",
        "port": 5432,
        "database": "tcc_cse_cic_ids",
        "user": "postgres",
        "password": "63aUM6Tjh7",
        "sslmode": "require"  # use "require" no RDS
    },
    "table": "network_flows",           # nome da tabela no Postgres (ajustado para sua tabela)
    "timestamp_col": "timestamp",      # coluna de timestamp (minuscula conforme sua tabela)
    "label_col": "label",              # coluna de label (minuscula conforme sua tabela)
    "id_like_cols": [                    # colunas para descartar de modelagem (adapte se quiser manter)
        # nenhum campo de IP/ID explícito na sua tabela, mantenha vazio ou adicione se existir
    ],
    "categorical_cols": [                # tratar protocolo como categórica
        "protocol"
    ],
    "positive_label": "MALICIOUS",     # valor final após normalização do rótulo
    "negative_label": "BENIGN",        # valor final após normalização do rótulo
    "sample": {
        "enable": True,
        "rows": 200_000,                  # amostra total aproximada (ajuste conforme memória)
        "random_state": 42
    },
    "chunksize": 100_000,                # tamanho dos chunks na leitura
    "output_dir": "outputs",           # onde salvar gráficos e relatórios
    "models": {
        "rf": {
            "n_estimators": 200,
            "max_depth": None,
            "n_jobs": -1,
            "random_state": 42
        },
        "logreg": {
            "max_iter": 200,
            "n_jobs": -1
        }
    },
    "trend": {
        "freq": "H",                     # agregação temporal: 'H' hora, 'D' dia
        "forecast_steps": 24 * 7,         # horizonte de previsão
        "order": [1, 0, 1],               # SARIMA (p,d,q)
        "seasonal_order": [1, 0, 1, 24]   # sazonalidade diária para dados horários
    }
}

# =====================
# Utils
# =====================

def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def save_json(obj, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def make_engine(cfg: dict):
    d = cfg["db"]
    url = f"postgresql+psycopg2://{d['user']}:{d['password']}@{d['host']}:{d['port']}/{d['database']}?sslmode={d['sslmode']}"
    return create_engine(url, pool_pre_ping=True)


def normalize_labels(series: pd.Series) -> pd.Series:
    # Converte rótulos do CICIDS: tudo que não for benign vira malicioso
    s = series.astype(str).str.strip().str.upper()
    return np.where(s.isin(["BENIGN", "NORMAL", "BENIGNO"]), CONFIG["negative_label"], CONFIG["positive_label"])


def infer_feature_columns(df: pd.DataFrame, id_like: List[str], label_col: str) -> Tuple[List[str], List[str]]:
    drop_cols = set([c for c in id_like if c in df.columns] + [label_col])
    numeric_cols = [c for c in df.columns if c not in drop_cols and pd.api.types.is_numeric_dtype(df[c])]
    categorical_cols = [c for c in CONFIG["categorical_cols"] if c in df.columns and c not in drop_cols]
    return numeric_cols, categorical_cols


def read_sampled(engine, table: str, label_col: str, ts_col: str, rows: Optional[int], chunksize: int, random_state: int) -> pd.DataFrame:
    # Lê somente colunas necessárias para definir amostra estratificada
    with engine.connect() as con:
        # Conta total
        total = con.execute(text(f"SELECT COUNT(*) FROM {table}"))
        total = list(total)[0][0]
        print(f"Total de linhas na tabela: {total}")

    # Estratégia: se rows None, lê tudo em chunks, senão faz amostra usando TABLESAMPLE SYSTEM.
    # Nem todos os Postgres têm SYSTEM TABLESAMPLE habilitado no RDS. Fallback: amostra após leitura parcial.
    target_rows = rows if rows else total

    cols_sql = "*"  # simplificação, pode trocar por lista de colunas
    base_sql = f"SELECT {cols_sql} FROM {table}"

    # Leitura em chunks
    rng = np.random.default_rng(random_state)
    dfs = []
    read_rows = 0
    for chunk in pd.read_sql(text(base_sql), engine, chunksize=chunksize):
        # Normaliza rótulo
        if label_col not in chunk.columns:
            raise ValueError(f"Coluna de rótulo '{label_col}' não encontrada no chunk")
        chunk[label_col] = normalize_labels(chunk[label_col])

        # Drop linhas sem timestamp
        if ts_col in chunk.columns:
            chunk = chunk[~chunk[ts_col].isna()].copy()
        
        if rows is not None:
            # Subamostra estratificada por label dentro do chunk
            frac = min(1.0, max(0.05, target_rows / max(total, 1)))
            # Aplica amostra por classe
            sampled = (
                chunk.groupby(label_col, group_keys=False)
                .apply(lambda g: g.sample(frac=frac, random_state=random_state) if len(g) > 0 else g)
            )
            dfs.append(sampled)
            read_rows += len(sampled)
            if read_rows >= target_rows * 1.2:  # margem
                break
        else:
            dfs.append(chunk)

    df = pd.concat(dfs, ignore_index=True)

    if rows is not None and len(df) > rows:
        # ajuste fino da amostra final, estratificado
        df = (
            df.groupby(label_col, group_keys=False)
              .apply(lambda g: g.sample(n=min(len(g), math.ceil(rows * len(g) / len(df))), random_state=random_state))
              .reset_index(drop=True)
        )

    return df


# =====================
# EDA
# =====================

def plot_class_balance(df: pd.DataFrame, label_col: str, out_dir: str):
    counts = df[label_col].value_counts().sort_index()
    plt.figure()
    counts.plot(kind="bar")
    plt.title("Distribuição de classes")
    plt.xlabel("Classe")
    plt.ylabel("Contagem")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "01_class_balance.png"))
    plt.close()


def plot_top_ports(df: pd.DataFrame, out_dir: str):
    # Suporta nomes em snake_case e em formato com espaços
    possible_cols = ["dst_port", "src_port", "destination_port", "source_port", "Dst Port", "Src Port", "Destination Port", "Source Port"]
    cols = [c for c in possible_cols if c in df.columns]
    for col in cols:
        top = df[col].value_counts().head(15)
        plt.figure()
        top.plot(kind="bar")
        plt.title(f"Top {len(top)} {col}")
        plt.xlabel(col)
        plt.ylabel("Contagem")
        plt.tight_layout()
        safe_name = col.replace(' ', '_').lower()
        plt.savefig(os.path.join(out_dir, f"02_top_{safe_name}.png"))
        plt.close()


def plot_protocols(df: pd.DataFrame, out_dir: str):
    possible = ["protocol", "Protocol", "ProtocolName"]
    cols = [c for c in possible if c in df.columns]
    for col in cols:
        vc = df[col].astype(str).value_counts().head(15)
        plt.figure()
        vc.plot(kind="bar")
        plt.title(f"Protocolos – {col}")
        plt.xlabel(col)
        plt.ylabel("Contagem")
        plt.tight_layout()
        plt.savefig(os.path.join(out_dir, f"03_protocols_{col.lower()}.png"))
        plt.close()


def plot_time_series_attacks(df: pd.DataFrame, ts_col: str, label_col: str, freq: str, out_dir: str) -> pd.DataFrame:
    ts = pd.to_datetime(df[ts_col], errors="coerce")
    m = pd.Series((df[label_col] != CONFIG["negative_label"]).astype(int).values, index=ts)
    agg = m.resample(freq).sum().dropna()

    plt.figure()
    agg.plot()
    plt.title(f"Ataques por {freq}")
    plt.xlabel("Tempo")
    plt.ylabel("Contagem de ataques")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, f"04_attacks_over_time_{freq}.png"))
    plt.close()

    return agg.to_frame(name="attacks")


# =====================
# Modelagem – Classificação
# =====================

def build_classification_pipeline(num_cols: List[str], cat_cols: List[str]):
    transformers = []
    if num_cols:
        transformers.append(("num", StandardScaler(with_mean=False), num_cols))
    if cat_cols:
        transformers.append(("cat", "passthrough", cat_cols))

    pre = ColumnTransformer(transformers=transformers, remainder="drop")

    rf = RandomForestClassifier(**CONFIG["models"]["rf"])  # baseline forte
    pipe_rf = ImbPipeline(steps=[
        ("pre", pre),
        ("smote", SMOTE(random_state=42)),
        ("clf", rf)
    ])

    logreg = LogisticRegression(**CONFIG["models"]["logreg"])  # baseline linear
    pipe_lr = ImbPipeline(steps=[
        ("pre", pre),
        ("smote", SMOTE(random_state=42)),
        ("clf", logreg)
    ])

    return {"random_forest": pipe_rf, "logreg": pipe_lr}


def evaluate_model(name: str, model, X_test: pd.DataFrame, y_test: pd.Series, out_dir: str) -> dict:
    y_pred = model.predict(X_test)
    try:
        y_prob = model.predict_proba(X_test)[:, 1]
        auc = roc_auc_score(y_test, y_prob)
    except Exception:
        auc = None

    cr = classification_report(y_test, y_pred, output_dict=True)
    cm = confusion_matrix(y_test, y_pred)

    # Salva matriz de confusão
    plt.figure()
    cm_df = pd.DataFrame(cm, index=[CONFIG["negative_label"], CONFIG["positive_label"]], columns=["Pred Neg", "Pred Pos"])
    cm_df.plot(kind="bar")
    plt.title(f"Matriz de confusão – {name}")
    plt.xlabel("Classe real")
    plt.ylabel("Contagem")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, f"10_confusion_{name}.png"))
    plt.close()

    return {"classification_report": cr, "roc_auc": auc}


# =====================
# Tendência – SARIMAX
# =====================

def fit_forecast_sarimax(series: pd.Series, steps: int, order: List[int], seasonal_order: List[int], out_dir: str) -> pd.DataFrame:
    model = SARIMAX(series, order=tuple(order), seasonal_order=tuple(seasonal_order), enforce_stationarity=False, enforce_invertibility=False)
    res = model.fit(disp=False)
    fc = res.get_forecast(steps=steps)
    pred = fc.predicted_mean
    conf = fc.conf_int(alpha=0.2)

    # Plot
    plt.figure()
    series.plot(label="observado")
    pred.index = pd.date_range(series.index[-1] + (series.index[1] - series.index[0]), periods=steps, freq=series.index.freq)
    pred.plot(label="previsão")
    plt.fill_between(conf.index, conf.iloc[:, 0], conf.iloc[:, 1], alpha=0.2)
    plt.title("Previsão de ataques")
    plt.xlabel("Tempo")
    plt.ylabel("Contagem de ataques")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "20_forecast_attacks.png"))
    plt.close()

    out = pd.DataFrame({
        "forecast": pred,
        "lo": conf.iloc[:, 0],
        "hi": conf.iloc[:, 1]
    })
    return out


# =====================
# Main
# =====================

def main():
    ensure_dir(CONFIG["output_dir"])
    save_json(CONFIG, os.path.join(CONFIG["output_dir"], "config_used.json"))

    engine = make_engine(CONFIG)
    df = read_sampled(
        engine=engine,
        table=CONFIG["table"],
        label_col=CONFIG["label_col"],
        ts_col=CONFIG["timestamp_col"],
        rows=CONFIG["sample"]["rows"] if CONFIG["sample"]["enable"] else None,
        chunksize=CONFIG["chunksize"],
        random_state=CONFIG["sample"]["random_state"]
    )

    # Normaliza target binário
    df[CONFIG["label_col"]] = normalize_labels(df[CONFIG["label_col"]])

    # EDA
    plot_class_balance(df, CONFIG["label_col"], CONFIG["output_dir"])
    plot_top_ports(df, CONFIG["output_dir"])
    plot_protocols(df, CONFIG["output_dir"])
    attacks_ts = plot_time_series_attacks(df, CONFIG["timestamp_col"], CONFIG["label_col"], CONFIG["trend"]["freq"], CONFIG["output_dir"])

    # Features
    num_cols, cat_cols = infer_feature_columns(df, CONFIG["id_like_cols"], CONFIG["label_col"])

    X = df[num_cols + cat_cols].copy()
    y = (df[CONFIG["label_col"]] != CONFIG["negative_label"]).astype(int)

    # Split estratificado
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=42
    )

    # Pipelines
    models = build_classification_pipeline(num_cols, cat_cols)

    results = {}
    for name, pipe in models.items():
        pipe.fit(X_train, y_train)
        metrics = evaluate_model(name, pipe, X_test, y_test, CONFIG["output_dir"])
        results[name] = metrics

    # Escolhe melhor por ROC AUC se disponível, senão f1 na classe positiva
    best_name = max(results.keys(), key=lambda k: (results[k]["roc_auc"] if results[k]["roc_auc"] is not None else results[k]["classification_report"]["1"]["f1-score"]))
    best_model = models[best_name]

    # Salva resumo de métricas
    save_json(results, os.path.join(CONFIG["output_dir"], "metrics_classification.json"))

    # Importâncias de features se RandomForest
    if hasattr(best_model.named_steps["clf"], "feature_importances_"):
        # Reconstrói nomes após ColumnTransformer: num seguidos de cat
        feat_names = num_cols + cat_cols
        importances = best_model.named_steps["clf"].feature_importances_
        fi = pd.DataFrame({"feature": feat_names, "importance": importances}).sort_values("importance", ascending=False).head(20)
        plt.figure()
        fi.set_index("feature")["importance"].plot(kind="barh")
        plt.title("Top 20 features")
        plt.xlabel("Importância")
        plt.tight_layout()
        plt.savefig(os.path.join(CONFIG["output_dir"], "11_top_features.png"))
        plt.close()
        fi.to_csv(os.path.join(CONFIG["output_dir"], "top_features.csv"), index=False)

    # Tendência com SARIMAX
    if len(attacks_ts) >= 48:  # precisa de pelo menos 2 dias em H
        forecast_df = fit_forecast_sarimax(
            series=attacks_ts["attacks"],
            steps=CONFIG["trend"]["forecast_steps"],
            order=CONFIG["trend"]["order"],
            seasonal_order=CONFIG["trend"]["seasonal_order"],
            out_dir=CONFIG["output_dir"]
        )
        forecast_df.to_csv(os.path.join(CONFIG["output_dir"], "forecast_attacks.csv"))

    # Export amostra rotulada para auditoria
    sample_csv = os.path.join(CONFIG["output_dir"], "sample_labeled.csv")
    df.head(50_000).to_csv(sample_csv, index=False)

    print("Finalizado. Artefatos gerados na pasta:", CONFIG["output_dir"])


if __name__ == "__main__":
    main()


# =====================
# SQL Úteis no Postgres (colar direto no DBeaver p.ex.)
# =====================
# 1) Conferir colunas e amostra
#   SELECT * FROM network_flows LIMIT 50;
#   SELECT COUNT(*), MIN(timestamp), MAX(timestamp) FROM network_flows;
# 2) Checar desbalanceamento
#   SELECT UPPER(label) AS label, COUNT(*) FROM network_flows GROUP BY 1 ORDER BY 2 DESC;
# 3) Amostra estratificada simples no SQL (opcional, aproximação)
#   CREATE TEMP TABLE tmp_sample AS
#   SELECT * FROM (
#     SELECT *, ROW_NUMBER() OVER (PARTITION BY (UPPER(label) IN ('BENIGN','NORMAL','BENIGNO')) ORDER BY random()) AS rn
#     FROM network_flows
#   ) t
#   WHERE rn <= 150000;
#   SELECT COUNT(*) FROM tmp_sample;
    