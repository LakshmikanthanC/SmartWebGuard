import os
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Conv1D, MaxPooling1D, Flatten, Dense, Dropout, BatchNormalization, Input
from tensorflow.keras.callbacks import EarlyStopping, ReduceLROnPlateau, ModelCheckpoint
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.optimizers import Adam
from preprocess import DataPreprocessor
from utils.evaluation import evaluate_model
from config import MODEL_DIR, CNN_CONFIG, DATA_DIR


def build_model(input_shape, num_classes):
    c = CNN_CONFIG
    model = Sequential([
        Input(shape=input_shape),
        Conv1D(c["filters"][0], c["kernel_size"], activation="relu", padding="same"),
        BatchNormalization(), MaxPooling1D(2), Dropout(c["dropout_rate"]),
        Conv1D(c["filters"][1], c["kernel_size"], activation="relu", padding="same"),
        BatchNormalization(), MaxPooling1D(2), Dropout(c["dropout_rate"]),
        Conv1D(c["filters"][2], c["kernel_size"], activation="relu", padding="same"),
        BatchNormalization(), Dropout(c["dropout_rate"]),
        Flatten(),
        Dense(c["dense_units"][0], activation="relu"), BatchNormalization(), Dropout(0.4),
        Dense(c["dense_units"][1], activation="relu"), BatchNormalization(), Dropout(0.3),
        Dense(num_classes, activation="softmax")
    ])
    model.compile(optimizer=Adam(learning_rate=c["learning_rate"]),
                  loss="categorical_crossentropy", metrics=["accuracy"])
    return model


def train():
    print("="*50 + "\n  AI-NIDS: CNN Training\n" + "="*50)
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(MODEL_DIR, exist_ok=True)

    prep = DataPreprocessor()
    try:
        result = prep.run("KDDTrain+.txt")
    except FileNotFoundError:
        print("[WARN] Dataset not found — generating synthetic data...")
        from utils.feature_engineering import generate_synthetic_data
        df = generate_synthetic_data(15000)
        df.to_csv(os.path.join(DATA_DIR, "KDDTrain+.txt"), index=False, header=False)
        result = prep.run("KDDTrain+.txt")

    X_train, X_test, y_train, y_test, num_classes, label_enc = result
    y_train_c = to_categorical(y_train, num_classes)
    y_test_c = to_categorical(y_test, num_classes)

    model = build_model((X_train.shape[1], 1), num_classes)
    model.summary()

    callbacks = [
        EarlyStopping(monitor="val_loss", patience=10, restore_best_weights=True),
        ReduceLROnPlateau(monitor="val_loss", factor=0.5, patience=5, min_lr=1e-6),
        ModelCheckpoint(os.path.join(MODEL_DIR, "best_model.keras"),
                        monitor="val_accuracy", save_best_only=True)
    ]

    history = model.fit(X_train, y_train_c, epochs=CNN_CONFIG["epochs"],
                        batch_size=CNN_CONFIG["batch_size"],
                        validation_split=CNN_CONFIG["validation_split"],
                        callbacks=callbacks, verbose=1)

    model.save(os.path.join(MODEL_DIR, "nids_cnn_model.keras"))
    metrics = evaluate_model(model, X_test, y_test, label_enc, history)
    print("\n[SUCCESS] Training complete!")
    return model, metrics


if __name__ == "__main__":
    train()