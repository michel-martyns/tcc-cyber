import datetime
import random
import psycopg2
from psycopg2 import sql

# =================================================================
# Configuração do Banco de Dados
# ATENÇÃO: Preencha as suas credenciais aqui.
# =================================================================
DATABASE_CONFIG = {
    'host': 'tcc-cse-cic-ids.c3o0mem8emzt.us-east-2.rds.amazonaws.com',
    'dbname': 'tcc_cse_cic_ids',
    'user': 'postgres',
    'password': '63aUM6Tjh7',
    'port': '5432'
}

def generate_and_insert_data(db_config, start_date, end_date, min_records_per_day=100000, batch_size=5000):
    """
    Gera dados fictícios para o dataset CIC-IDS2018 e os insere diretamente no banco de dados.

    Args:
        db_config (dict): Dicionário com as configurações do banco de dados.
        start_date (datetime.date): Data de início da geração.
        end_date (datetime.date): Data de fim da geração.
        min_records_per_day (int): Número mínimo de registros por dia.
        batch_size (int): Tamanho do lote de inserção.
    """
    attack_types = [
        'Brute Force', 'DDoS', 'DoS GoldenEye', 'DoS Hulk',
        'DoS Slowhttptest', 'DoS slowloris', 'Heartbleed',
        'Infiltration', 'PortScan', 'Web Attack Brute Force',
        'Web Attack Sql Injection', 'Web Attack XSS'
    ]
    labels = ['Benign'] + attack_types

    conn = None
    try:
        # Tenta conectar ao banco de dados
        print("Tentando conectar ao banco de dados...")
        conn = psycopg2.connect(**db_config)
        conn.autocommit = False
        cursor = conn.cursor()
        print("Conexão bem-sucedida!")

        current_date = start_date
        while current_date <= end_date:
            daily_records = random.randint(min_records_per_day, int(min_records_per_day * 1.2))

            # Simula um pico de ataque em datas específicas
            is_attack_day = current_date in [
                datetime.date(2025, 4, 15), datetime.date(2025, 5, 20), datetime.date(2025, 6, 10)
            ]

            records = []
            for i in range(daily_records):
                # Determina se o registro é um ataque (probabilidade maior em dias de pico)
                is_attack = is_attack_day or random.random() < 0.1  # 10% de chance de ser ataque em dias normais

                # Atribui o rótulo (label)
                if is_attack:
                    label = random.choice(attack_types)
                else:
                    label = 'Benign'

                # Gera valores fictícios para cada coluna
                dst_port = random.randint(1, 65535)
                protocol = random.choice([6, 17]) # TCP ou UDP
                timestamp = datetime.datetime.combine(current_date, datetime.time(random.randint(0, 23), random.randint(0, 59), random.randint(0, 59)))
                flow_duration = random.randint(1000, 100000000)
                tot_fwd_pkts = random.randint(1, 2000)
                tot_bwd_pkts = random.randint(1, 2000)
                totlen_fwd_pkts = random.randint(50, 50000)
                totlen_bwd_pkts = random.randint(50, 50000)
                fwd_pkt_len_max = random.randint(20, 1500)
                fwd_pkt_len_min = random.randint(10, 100)
                fwd_pkt_len_mean = (fwd_pkt_len_max + fwd_pkt_len_min) / 2
                fwd_pkt_len_std = random.uniform(1.0, 50.0)
                bwd_pkt_len_max = random.randint(20, 1500)
                bwd_pkt_len_min = random.randint(10, 100)
                bwd_pkt_len_mean = (bwd_pkt_len_max + bwd_pkt_len_min) / 2
                bwd_pkt_len_std = random.uniform(1.0, 50.0)
                flow_byts_s = (totlen_fwd_pkts + totlen_bwd_pkts) / (flow_duration / 1000000.0)
                flow_pkts_s = (tot_fwd_pkts + tot_bwd_pkts) / (flow_duration / 1000000.0)
                flow_iat_mean = random.uniform(100.0, 100000.0)
                flow_iat_std = random.uniform(10.0, 5000.0)
                flow_iat_max = random.randint(5000, 500000)
                flow_iat_min = random.randint(1, 100)
                fwd_iat_tot = random.randint(1000, 100000000)
                fwd_iat_mean = random.uniform(100.0, 100000.0)
                fwd_iat_std = random.uniform(10.0, 5000.0)
                fwd_iat_max = random.randint(5000, 500000)
                fwd_iat_min = random.randint(1, 100)
                bwd_iat_tot = random.randint(1000, 100000000)
                bwd_iat_mean = random.uniform(100.0, 100000.0)
                bwd_iat_std = random.uniform(10.0, 5000.0)
                bwd_iat_max = random.randint(5000, 500000)
                bwd_iat_min = random.randint(1, 100)
                fwd_psh_flags = random.choice([0, 1])
                bwd_psh_flags = 0
                fwd_urg_flags = 0
                bwd_urg_flags = 0
                fwd_header_len = random.randint(20, 1000)
                bwd_header_len = random.randint(20, 1000)
                fwd_pkts_s = (tot_fwd_pkts) / (flow_duration / 1000000.0)
                bwd_pkts_s = (tot_bwd_pkts) / (flow_duration / 1000000.0)
                pkt_len_min = min(fwd_pkt_len_min, bwd_pkt_len_min)
                pkt_len_max = max(fwd_pkt_len_max, bwd_pkt_len_max)
                pkt_len_mean = (fwd_pkt_len_mean + bwd_pkt_len_mean) / 2
                pkt_len_std = random.uniform(1.0, 50.0)
                pkt_len_var = pkt_len_std**2
                fin_flag_cnt = random.randint(0, 2)
                syn_flag_cnt = random.randint(0, 2)
                rst_flag_cnt = random.randint(0, 2)
                psh_flag_cnt = random.randint(0, 2)
                ack_flag_cnt = random.randint(0, 2)
                urg_flag_cnt = random.randint(0, 2)
                cwe_flag_count = 0
                ece_flag_cnt = 0
                down_up_ratio = random.uniform(0.1, 10.0)
                pkt_size_avg = random.uniform(100.0, 1000.0)
                fwd_seg_size_avg = random.uniform(100.0, 1000.0)
                bwd_seg_size_avg = random.uniform(100.0, 1000.0)
                fwd_byts_b_avg = random.uniform(10.0, 500.0)
                fwd_pkts_b_avg = random.uniform(1.0, 10.0)
                fwd_blk_rate_avg = random.uniform(0.1, 1.0)
                bwd_byts_b_avg = random.uniform(10.0, 500.0)
                bwd_pkts_b_avg = random.uniform(1.0, 10.0)
                bwd_blk_rate_avg = random.uniform(0.1, 1.0)
                subflow_fwd_pkts = random.randint(1, 100)
                subflow_fwd_byts = random.randint(100, 10000)
                subflow_bwd_pkts = random.randint(1, 100)
                subflow_bwd_byts = random.randint(100, 10000)
                init_fwd_win_byts = random.randint(100, 65535)
                init_bwd_win_byts = random.randint(100, 65535)
                fwd_act_data_pkts = random.randint(1, 100)
                fwd_seg_size_min = random.randint(10, 100)
                active_mean = random.uniform(1000.0, 1000000.0)
                active_std = random.uniform(100.0, 50000.0)
                active_max = random.randint(5000, 1000000)
                active_min = random.randint(100, 5000)
                idle_mean = random.uniform(10000.0, 10000000.0)
                idle_std = random.uniform(1000.0, 500000.0)
                idle_max = random.randint(50000, 10000000)
                idle_min = random.randint(5000, 100000)

                source_file = "fictitious_data.csv"
                flow_id = f"fictitious_{random.randint(1, 999999999)}"
                src_ip = f"192.168.1.{random.randint(1, 254)}"
                src_port = str(random.randint(49152, 65535))
                dst_ip = f"10.0.0.{random.randint(1, 254)}"

                # Adiciona o registro à lista para inserção em lote
                records.append((
                    dst_port, protocol, timestamp, flow_duration, tot_fwd_pkts, tot_bwd_pkts,
                    totlen_fwd_pkts, totlen_bwd_pkts, fwd_pkt_len_max, fwd_pkt_len_min, fwd_pkt_len_mean,
                    fwd_pkt_len_std, bwd_pkt_len_max, bwd_pkt_len_min, bwd_pkt_len_mean, bwd_pkt_len_std,
                    flow_byts_s, flow_pkts_s, flow_iat_mean, flow_iat_std, flow_iat_max, flow_iat_min,
                    fwd_iat_tot, fwd_iat_mean, fwd_iat_std, fwd_iat_max, fwd_iat_min, bwd_iat_tot,
                    bwd_iat_mean, bwd_iat_std, bwd_iat_max, bwd_iat_min, fwd_psh_flags, bwd_psh_flags,
                    fwd_urg_flags, bwd_urg_flags, fwd_header_len, bwd_header_len, fwd_pkts_s, bwd_pkts_s,
                    pkt_len_min, pkt_len_max, pkt_len_mean, pkt_len_std, pkt_len_var, fin_flag_cnt,
                    syn_flag_cnt, rst_flag_cnt, psh_flag_cnt, ack_flag_cnt, urg_flag_cnt, cwe_flag_count,
                    ece_flag_cnt, down_up_ratio, pkt_size_avg, fwd_seg_size_avg, bwd_seg_size_avg,
                    fwd_byts_b_avg, fwd_pkts_b_avg, fwd_blk_rate_avg, bwd_byts_b_avg, bwd_pkts_b_avg,
                    bwd_blk_rate_avg, subflow_fwd_pkts, subflow_fwd_byts, subflow_bwd_pkts, subflow_bwd_byts,
                    init_fwd_win_byts, init_bwd_win_byts, fwd_act_data_pkts, fwd_seg_size_min,
                    active_mean, active_std, active_max, active_min, idle_mean, idle_std, idle_max,
                    idle_min, label, source_file, flow_id, src_ip, src_port, dst_ip
                ))

                # Insere em lotes
                if len(records) >= batch_size:
                    insert_records(cursor, records)
                    conn.commit()
                    records = []

            # Insere os registros restantes do dia
            if records:
                insert_records(cursor, records)
                conn.commit()

            print(f"Dados para o dia {current_date} inseridos. Total: {daily_records} registros.")
            current_date += datetime.timedelta(days=1)

    except (Exception, psycopg2.Error) as error:
        print(f"Erro ao se conectar ao PostgreSQL ou ao inserir dados: {error}")
    finally:
        if conn:
            cursor.close()
            conn.close()
            print("Conexão com o PostgreSQL fechada.")

def insert_records(cursor, records):
    """
    Insere uma lista de registros em lote.
    """
    columns = [
        "dst_port", "protocol", "timestamp", "flow_duration", "tot_fwd_pkts", "tot_bwd_pkts",
        "totlen_fwd_pkts", "totlen_bwd_pkts", "fwd_pkt_len_max", "fwd_pkt_len_min", "fwd_pkt_len_mean",
        "fwd_pkt_len_std", "bwd_pkt_len_max", "bwd_pkt_len_min", "bwd_pkt_len_mean", "bwd_pkt_len_std",
        "flow_byts_s", "flow_pkts_s", "flow_iat_mean", "flow_iat_std", "flow_iat_max", "flow_iat_min",
        "fwd_iat_tot", "fwd_iat_mean", "fwd_iat_std", "fwd_iat_max", "fwd_iat_min", "bwd_iat_tot",
        "bwd_iat_mean", "bwd_iat_std", "bwd_iat_max", "bwd_iat_min", "fwd_psh_flags", "bwd_psh_flags",
        "fwd_urg_flags", "bwd_urg_flags", "fwd_header_len", "bwd_header_len", "fwd_pkts_s", "bwd_pkts_s",
        "pkt_len_min", "pkt_len_max", "pkt_len_mean", "pkt_len_std", "pkt_len_var", "fin_flag_cnt",
        "syn_flag_cnt", "rst_flag_cnt", "psh_flag_cnt", "ack_flag_cnt", "urg_flag_cnt", "cwe_flag_count",
        "ece_flag_cnt", "down_up_ratio", "pkt_size_avg", "fwd_seg_size_avg", "bwd_seg_size_avg",
        "fwd_byts_b_avg", "fwd_pkts_b_avg", "fwd_blk_rate_avg", "bwd_byts_b_avg", "bwd_pkts_b_avg",
        "bwd_blk_rate_avg", "subflow_fwd_pkts", "subflow_fwd_byts", "subflow_bwd_pkts", "subflow_bwd_byts",
        "init_fwd_win_byts", "init_bwd_win_byts", "fwd_act_data_pkts", "fwd_seg_size_min",
        "active_mean", "active_std", "active_max", "active_min", "idle_mean", "idle_std", "idle_max",
        "idle_min", "label", "source_file", "flow_id", "src_ip", "src_port", "dst_ip"
    ]

    insert_query = sql.SQL("INSERT INTO public.network_flows ({}) VALUES ({})").format(
        sql.SQL(', ').join(map(sql.Identifier, columns)),
        sql.SQL(', ').join(sql.Placeholder() * len(columns))
    )

    cursor.executemany(insert_query, records)

if __name__ == '__main__':
    start_date = datetime.date(2017, 3, 2)
    end_date = datetime.date(2017, 6, 30)
    generate_and_insert_data(DATABASE_CONFIG, start_date, end_date)