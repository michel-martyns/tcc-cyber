import os
import pandas as pd
import matplotlib.pyplot as plt

# =====================
# EDA
# =====================

def plot_class_balance(df: pd.DataFrame, label_col: str, out_dir: str):
    """
    Gera gráfico de barras mostrando a distribuição de classes (benigno vs malicioso).

    Args:
        df (pd.DataFrame): DataFrame com os dados.
        label_col (str): Nome da coluna de rótulo.
        out_dir (str): Caminho da pasta onde salvar o gráfico.
    """
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
    """
    Gera gráficos dos top 15 ports mais frequentes (destino e origem).

    Args:
        df (pd.DataFrame): DataFrame com os dados.
        out_dir (str): Caminho da pasta onde salvar os gráficos.
    """
    possible_cols = [
        "dst_port", "src_port", "destination_port", "source_port",
        "Dst Port", "Src Port", "Destination Port", "Source Port"
    ]
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
    """
    Gera gráfico dos principais protocolos usados no tráfego.

    Args:
        df (pd.DataFrame): DataFrame com os dados.
        out_dir (str): Caminho da pasta onde salvar os gráficos.
    """
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


def plot_time_series_attacks(df: pd.DataFrame, ts_col: str, label_col: str, freq: str, out_dir: str, negative_label: str) -> pd.DataFrame:
    """
    Gera série temporal de ataques ao longo do tempo, agregada pela frequência desejada.

    Args:
        df (pd.DataFrame): DataFrame com os dados.
        ts_col (str): Nome da coluna de timestamp.
        label_col (str): Nome da coluna de rótulo.
        freq (str): Frequência de agregação ('H' hora, 'D' dia, etc).
        out_dir (str): Caminho da pasta onde salvar o gráfico.
        negative_label (str): Valor usado para representar tráfego benigno.

    Returns:
        pd.DataFrame: Série temporal agregada com contagem de ataques.
    """
    ts = pd.to_datetime(df[ts_col], errors="coerce")
    m = pd.Series((df[label_col] != negative_label).astype(int).values, index=ts)
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
