import os
import pandas as pd
import matplotlib.pyplot as plt
from statsmodels.tsa.statespace.sarimax import SARIMAX

# =====================
# Tendência – SARIMAX
# =====================

def fit_sarimax(
    ts: pd.Series,
    order=(1, 1, 1),
    seasonal_order=(0, 1, 1, 24),
    steps: int = 24,
    out_dir: str = "./out"
) -> pd.DataFrame:
    """
    Ajusta um modelo SARIMAX em uma série temporal e gera previsão.

    Args:
        ts (pd.Series): Série temporal de ataques agregados.
        order (tuple): Ordem do modelo ARIMA (p, d, q).
        seasonal_order (tuple): Ordem sazonal (P, D, Q, s).
        steps (int): Passos futuros para previsão.
        out_dir (str): Diretório de saída para salvar resultados.

    Returns:
        pd.DataFrame: DataFrame com histórico, previsão e intervalo de confiança.
    """
    # Ajusta o modelo
    model = SARIMAX(ts, order=order, seasonal_order=seasonal_order, enforce_stationarity=False, enforce_invertibility=False)
    results = model.fit(disp=False)

    # Faz previsão
    forecast = results.get_forecast(steps=steps)
    pred_ci = forecast.conf_int()

    # Gráfico
    plt.figure(figsize=(10, 4))
    ts.plot(label="observado")
    forecast.predicted_mean.plot(label="previsto", alpha=0.7)
    plt.fill_between(pred_ci.index, pred_ci.iloc[:, 0], pred_ci.iloc[:, 1], color="gray", alpha=0.3)
    plt.title("Previsão SARIMAX")
    plt.xlabel("Tempo")
    plt.ylabel("Ataques")
    plt.legend()
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, "sarimax_forecast.png"))
    plt.close()

    # Retorna resultados em DataFrame
    df_forecast = pd.DataFrame({
        "forecast": forecast.predicted_mean,
        "lower_ci": pred_ci.iloc[:, 0],
        "upper_ci": pred_ci.iloc[:, 1],
    })
    return df_forecast
