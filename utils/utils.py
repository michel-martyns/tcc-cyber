import os
import json
import math
from typing import List, Tuple, Optional

import numpy as np
import pandas as pd
from sqlalchemy import create_engine, text


def ensure_dir(path: str):
    """
    Garante que o diretório existe.
    Caso não exista, cria automaticamente.

    Args:
        path (str): Caminho do diretório.
    """
    os.makedirs(path, exist_ok=True)


def save_json(obj, path: str):
    """
    Salva um objeto Python como arquivo JSON.

    Args:
        obj: Objeto a ser serializado (dict, list, etc).
        path (str): Caminho do arquivo de saída.
    """
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def make_engine(cfg: dict):
    """
    Cria engine SQLAlchemy para conexão com PostgreSQL.

    Args:
        cfg (dict): Dicionário com parâmetros de conexão.
            Exemplo:
            {
                "db": {
                    "host": "...",
                    "port": 5432,
                    "database": "...",
                    "user": "...",
                    "password": "...",
                    "sslmode": "require"
                }
            }

    Returns:
        sqlalchemy.Engine: Conexão configurada.
    """
    d = cfg["db"]
    url = f"postgresql+psycopg2://{d['user']}:{d['password']}@{d['host']}:{d['port']}/{d['database']}?sslmode={d['sslmode']}"
    return create_engine(url, pool_pre_ping=True)


def normalize_labels(series: pd.Series, negative_label="BENIGN", positive_label="ATTACK") -> pd.Series:
    """
    Normaliza rótulos do dataset CICIDS:
    - Valores "BENIGN", "NORMAL", "BENIGNO" viram classe negativa.
    - Todos os demais viram classe positiva.

    Args:
        series (pd.Series): Coluna de rótulos original.
        negative_label (str): Nome da classe negativa no output.
        positive_label (str): Nome da classe positiva no output.

    Returns:
        np.ndarray: Array com rótulos normalizados.
    """
    s = series.astype(str).str.strip().str.upper()
    return np.where(
        s.isin(["BENIGN", "NORMAL", "BENIGNO"]),
        negative_label,
        positive_label
    )


def infer_feature_columns(df: pd.DataFrame, id_like: List[str], label_col: str) -> Tuple[List[str], List[str]]:
    """
    Identifica colunas numéricas e categóricas para modelagem.

    Args:
        df (pd.DataFrame): DataFrame com dados.
        id_like (List[str]): Lista de colunas de identificação a remover.
        label_col (str): Nome da coluna de rótulo (target).

    Returns:
        Tuple[List[str], List[str]]:
            - Lista de colunas numéricas
            - Lista de colunas categóricas
    """
    drop_cols = set([c for c in id_like if c in df.columns] + [label_col])
    numeric_cols = [c for c in df.columns if c not in drop_cols and pd.api.types.is_numeric_dtype(df[c])]
    categorical_cols = [c for c in CONFIG["categorical_cols"] if c in df.columns and c not in drop_cols]
    return numeric_cols, categorical_cols


def read_sampled(engine, table: str, label_col: str, ts_col: str, rows: Optional[int], 
                 chunksize: int, random_state: int, negative_label: str = "BENIGN", positive_label: str = "ATTACK") -> pd.DataFrame:
    """
    Lê dados de uma tabela PostgreSQL em chunks,
    com suporte a amostragem estratificada por rótulo.

    Args:
        engine: Conexão SQLAlchemy.
        table (str): Nome da tabela.
        label_col (str): Nome da coluna de rótulo.
        ts_col (str): Nome da coluna de timestamp.
        rows (Optional[int]): Quantidade aproximada de linhas desejada (None = tudo).
        chunksize (int): Número de linhas por chunk.
        random_state (int): Semente para reprodutibilidade.
        negative_label (str): Nome da classe negativa.
        positive_label (str): Nome da classe positiva.

    Returns:
        pd.DataFrame: DataFrame resultante (com ou sem amostragem).
    """
    # Conta total de linhas da tabela
    with engine.connect() as con:
        total = con.execute(text(f"SELECT COUNT(*) FROM {table}"))
        total = list(total)[0][0]
        print(f"Total de linhas na tabela: {total}")

    target_rows = rows if rows else total
    cols_sql = "*"
    base_sql = f"SELECT {cols_sql} FROM {table}"

    rng = np.random.default_rng(random_state)
    dfs = []
    read_rows = 0

    # Leitura em chunks
    for chunk in pd.read_sql(text(base_sql), engine, chunksize=chunksize):
        # Normaliza rótulo
        if label_col not in chunk.columns:
            raise ValueError(f"Coluna de rótulo '{label_col}' não encontrada no chunk")
        chunk[label_col] = normalize_labels(
            chunk[label_col],
            negative_label=negative_label,
            positive_label=positive_label
        )

        # Remove linhas sem timestamp
        if ts_col in chunk.columns:
            chunk = chunk[~chunk[ts_col].isna()].copy()

        if rows is not None:
            # Amostragem estratificada dentro do chunk
            frac = min(1.0, max(0.05, target_rows / max(total, 1)))
            sampled = (
                chunk.groupby(label_col, group_keys=False)
                     .apply(lambda g: g.sample(frac=frac, random_state=random_state) if len(g) > 0 else g)
            )
            dfs.append(sampled)
            read_rows += len(sampled)

            # Para quando já coletou o suficiente (com margem de 20%)
            if read_rows >= target_rows * 1.2:
                break
        else:
            dfs.append(chunk)

    df = pd.concat(dfs, ignore_index=True)

    # Ajuste final da amostra estratificada
    if rows is not None and len(df) > rows:
        df = (
            df.groupby(label_col, group_keys=False)
              .apply(lambda g: g.sample(
                  n=min(len(g), math.ceil(rows * len(g) / len(df))),
                  random_state=random_state
              ))
              .reset_index(drop=True)
        )

    return df
