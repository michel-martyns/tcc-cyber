import os
import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
import matplotlib.pyplot as plt

# =====================
# Modelagem – Classificação
# =====================

def train_and_evaluate(
    model, 
    X_train: pd.DataFrame, y_train: pd.Series,
    X_test: pd.DataFrame, y_test: pd.Series,
    out_dir: str, model_name: str
):
    """
    Treina um modelo de classificação, avalia no conjunto de teste e salva resultados.

    Args:
        model: Estimador sklearn (ou compatível).
        X_train (pd.DataFrame): Features de treino.
        y_train (pd.Series): Labels de treino.
        X_test (pd.DataFrame): Features de teste.
        y_test (pd.Series): Labels de teste.
        out_dir (str): Diretório de saída para salvar resultados.
        model_name (str): Nome do modelo para salvar arquivos.
    """
    # Treinamento
    model.fit(X_train, y_train)

    # Predição
    y_pred = model.predict(X_test)

    # Relatório de classificação
    report = classification_report(y_test, y_pred, digits=3, output_dict=True)
    report_df = pd.DataFrame(report).transpose()
    report_df.to_csv(os.path.join(out_dir, f"{model_name}_report.csv"))
    print(report_df)

    # Matriz de confusão
    cm = confusion_matrix(y_test, y_pred)
    plt.figure(figsize=(6, 6))
    plt.imshow(cm, cmap="Blues")
    plt.title(f"Matriz de Confusão – {model_name}")
    plt.colorbar()
    plt.xticks(range(len(np.unique(y_test))), np.unique(y_test))
    plt.yticks(range(len(np.unique(y_test))), np.unique(y_test))
    plt.xlabel("Predito")
    plt.ylabel("Real")
    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, cm[i, j], ha="center", va="center", color="red")
    plt.tight_layout()
    plt.savefig(os.path.join(out_dir, f"{model_name}_confusion_matrix.png"))
    plt.close()

    # Salva o modelo treinado
    joblib.dump(model, os.path.join(out_dir, f"{model_name}.joblib"))

    return model, report_df
