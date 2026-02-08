import numpy as np
import pandas as pd


def generate_synthetic_data(n_samples=10000, attack_ratio=0.4):
    """Generate realistic synthetic network traffic for training/demo."""
    np.random.seed(42)
    n_attack = int(n_samples * attack_ratio)
    n_normal = n_samples - n_attack

    def make_records(n, is_attack=False):
        records = {
            "duration": np.random.exponential(2 if is_attack else 20, n),
            "protocol_type": np.random.choice(["tcp", "udp", "icmp"], n,
                p=[0.4, 0.3, 0.3] if is_attack else [0.7, 0.2, 0.1]),
            "service": np.random.choice(
                ["http", "private", "ecr_i", "smtp", "other"] if is_attack
                else ["http", "https", "dns", "ssh", "ftp"], n),
            "flag": np.random.choice(
                ["SF", "S0", "REJ", "RSTO"] if is_attack
                else ["SF", "S0", "REJ"], n,
                p=[0.3, 0.3, 0.2, 0.2] if is_attack else [0.8, 0.1, 0.1]),
            "src_bytes": np.random.exponential(5000 if is_attack else 500, n),
            "dst_bytes": np.random.exponential(200 if is_attack else 1000, n),
            "land": np.random.choice([0, 1], n, p=[0.9, 0.1] if is_attack else [1.0, 0.0]),
            "wrong_fragment": np.random.choice([0, 1, 2, 3], n,
                p=[0.7, 0.1, 0.1, 0.1] if is_attack else [0.95, 0.03, 0.01, 0.01]),
            "urgent": np.zeros(n, dtype=int),
            "hot": np.random.poisson(3 if is_attack else 0.5, n),
            "num_failed_logins": np.random.poisson(2 if is_attack else 0, n),
            "logged_in": np.random.choice([0, 1], n, p=[0.5, 0.5] if is_attack else [0.1, 0.9]),
            "num_compromised": np.random.poisson(1 if is_attack else 0, n),
            "root_shell": np.random.choice([0, 1], n, p=[0.85, 0.15] if is_attack else [1.0, 0.0]),
            "su_attempted": np.zeros(n, dtype=int),
            "num_root": np.zeros(n, dtype=int),
            "num_file_creations": np.random.poisson(1 if is_attack else 0.1, n),
            "num_shells": np.zeros(n, dtype=int),
            "num_access_files": np.zeros(n, dtype=int),
            "num_outbound_cmds": np.zeros(n, dtype=int),
            "is_host_login": np.zeros(n, dtype=int),
            "is_guest_login": np.zeros(n, dtype=int),
            "count": np.random.poisson(200 if is_attack else 20, n),
            "srv_count": np.random.poisson(5 if is_attack else 15, n),
            "serror_rate": np.random.beta(10, 2, n) if is_attack else np.random.beta(1, 20, n),
            "srv_serror_rate": np.random.beta(10, 2, n) if is_attack else np.random.beta(1, 20, n),
            "rerror_rate": np.random.beta(5, 3, n) if is_attack else np.random.beta(1, 20, n),
            "srv_rerror_rate": np.random.beta(5, 3, n) if is_attack else np.random.beta(1, 20, n),
            "same_srv_rate": np.random.beta(2, 10, n) if is_attack else np.random.beta(10, 2, n),
            "diff_srv_rate": np.random.beta(10, 2, n) if is_attack else np.random.beta(2, 10, n),
            "srv_diff_host_rate": np.random.beta(10, 2, n) if is_attack else np.random.beta(2, 10, n),
            "dst_host_count": np.random.poisson(255 if is_attack else 100, n),
            "dst_host_srv_count": np.random.poisson(10 if is_attack else 50, n),
            "dst_host_same_srv_rate": np.random.beta(2, 10, n) if is_attack else np.random.beta(10, 2, n),
            "dst_host_diff_srv_rate": np.random.beta(10, 2, n) if is_attack else np.random.beta(2, 10, n),
            "dst_host_same_src_port_rate": np.random.beta(8, 3, n) if is_attack else np.random.beta(3, 5, n),
            "dst_host_srv_diff_host_rate": np.random.beta(10, 2, n) if is_attack else np.random.beta(2, 10, n),
            "dst_host_serror_rate": np.random.beta(10, 2, n) if is_attack else np.random.beta(1, 20, n),
            "dst_host_srv_serror_rate": np.random.beta(10, 2, n) if is_attack else np.random.beta(1, 20, n),
            "dst_host_rerror_rate": np.random.beta(5, 3, n) if is_attack else np.random.beta(1, 20, n),
            "dst_host_srv_rerror_rate": np.random.beta(5, 3, n) if is_attack else np.random.beta(1, 20, n),
        }
        return records

    normal = pd.DataFrame(make_records(n_normal, False))
    normal["attack_type"] = "normal"
    normal["difficulty_level"] = 0

    attack_types = {
        "dos": ["neptune", "smurf", "back", "teardrop", "pod"],
        "probe": ["ipsweep", "portsweep", "nmap", "satan"],
        "r2l": ["guess_passwd", "ftp_write", "warezclient", "warezmaster"],
        "u2r": ["buffer_overflow", "rootkit", "perl"]
    }
    attack_frames = []
    per_cat = n_attack // 4
    for cat, names in attack_types.items():
        n_cat = per_cat if cat != "u2r" else n_attack - 3 * per_cat
        df_a = pd.DataFrame(make_records(n_cat, True))
        df_a["attack_type"] = np.random.choice(names, n_cat)
        df_a["difficulty_level"] = np.random.randint(1, 21, n_cat)
        attack_frames.append(df_a)

    attacks = pd.concat(attack_frames, ignore_index=True)
    full = pd.concat([normal, attacks], ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
    return full