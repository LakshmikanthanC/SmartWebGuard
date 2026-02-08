import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.model_selection import train_test_split
import joblib
import os
from config import DATA_DIR, MODEL_DIR, NSL_KDD_COLUMNS, ATTACK_MAP


class DataPreprocessor:
    def __init__(self):
        self.label_encoders = {}
        self.scaler = MinMaxScaler()
        self.feature_columns = None

    def load_nsl_kdd(self, filename="KDDTrain+.txt"):
        filepath = os.path.join(DATA_DIR, filename)
        columns = NSL_KDD_COLUMNS + ["attack_type", "difficulty_level"]
        df = pd.read_csv(filepath, names=columns, header=None)
        df.drop("difficulty_level", axis=1, inplace=True)
        print(f"[INFO] Loaded {filepath}, shape: {df.shape}")
        return df

    def map_attacks(self, df):
        df["category"] = df["attack_type"].str.strip().str.lower().map(
            lambda x: ATTACK_MAP.get(x, "unknown")
        )
        df = df[df["category"] != "unknown"]
        print(f"[INFO] Categories:\n{df['category'].value_counts()}")
        return df

    def encode_features(self, df):
        cat_cols = df.select_dtypes(include=["object"]).columns
        cat_cols = [c for c in cat_cols if c not in ["attack_type", "category"]]
        for col in cat_cols:
            le = LabelEncoder()
            df[col] = le.fit_transform(df[col].astype(str))
            self.label_encoders[col] = le
        return df

    def encode_labels(self, df):
        le = LabelEncoder()
        df["label"] = le.fit_transform(df["category"])
        self.label_encoders["category"] = le
        print(f"[INFO] Labels: {dict(zip(le.classes_, le.transform(le.classes_)))}")
        return df, le

    def run(self, filename="KDDTrain+.txt", test_size=0.2):
        df = self.load_nsl_kdd(filename)
        df = self.map_attacks(df)
        df = self.encode_features(df)
        df, label_enc = self.encode_labels(df)

        feat_cols = [c for c in df.columns if c not in ["attack_type", "category", "label"]]
        self.feature_columns = feat_cols

        X = df[feat_cols].values.astype(np.float32)
        y = df["label"].values

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )

        X_train = self.scaler.fit_transform(X_train)
        X_test = self.scaler.transform(X_test)

        X_train = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
        X_test = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)

        self._save()
        num_classes = len(label_enc.classes_)
        print(f"[INFO] Train: {X_train.shape}, Test: {X_test.shape}, Classes: {num_classes}")
        return X_train, X_test, y_train, y_test, num_classes, label_enc

    def _save(self):
        os.makedirs(MODEL_DIR, exist_ok=True)
        joblib.dump(self.scaler, os.path.join(MODEL_DIR, "scaler.pkl"))
        joblib.dump(self.label_encoders, os.path.join(MODEL_DIR, "label_encoders.pkl"))
        joblib.dump(self.feature_columns, os.path.join(MODEL_DIR, "feature_columns.pkl"))

    def load_artifacts(self):
        self.scaler = joblib.load(os.path.join(MODEL_DIR, "scaler.pkl"))
        self.label_encoders = joblib.load(os.path.join(MODEL_DIR, "label_encoders.pkl"))
        self.feature_columns = joblib.load(os.path.join(MODEL_DIR, "feature_columns.pkl"))

    def transform_single(self, data_dict):
        df = pd.DataFrame([data_dict])
        for col, le in self.label_encoders.items():
            if col in df.columns and col != "category":
                try:
                    df[col] = le.transform(df[col].astype(str))
                except ValueError:
                    df[col] = 0
        for col in self.feature_columns:
            if col not in df.columns:
                df[col] = 0
        X = df[self.feature_columns].values.astype(np.float32)
        X = self.scaler.transform(X)
        return X.reshape(X.shape[0], X.shape[1], 1)