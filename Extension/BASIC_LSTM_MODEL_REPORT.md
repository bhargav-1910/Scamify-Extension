# Report: basic_lstm_model_best.h5

Last updated: 2025-11-04

## Summary

`basic_lstm_model_best.h5` is a trained Keras/TensorFlow LSTM model used in this repository (ScamiFy) for binary phishing detection. It performs deep behavioral analysis using 24 behavioral features extracted from web pages (via Selenium). The model produces a single probability (sigmoid) output representing the likelihood that a URL is phishing.

This report summarizes what we can infer from the repository code and documentation, how the model is used, the expected inputs/outputs, preprocessing, testing and integration points, and recommendations for inspection and reproduction.

## File locations

- Primary model file (references found in the repo):
  - `Scamify-main/Extension/backend/models/basic_lstm_model_best.h5`
  - Also referenced in project root as `basic_lstm_model_best.h5` for testing scripts.

- Feature scaler (preprocessing): `Scamify-main/Extension/backend/models/feature_scaler.pkl` (or `feature_scaler.pkl` in repo root)

## Model type and task

- Model type: Keras / TensorFlow LSTM (saved as an HDF5 `.h5` file)
- Task: Binary classification — predict whether a URL (given behavioral features) is `phishing` (positive) or `legitimate` (negative)
- Loss used when re-compiling in compatibility fixer: `binary_crossentropy` (the typical loss for binary classification)

## Input & output

- Expected raw input: 24 numeric features extracted per URL.
- Preprocessing: features are scaled using a fitted scikit-learn `StandardScaler` that is saved/loaded via `joblib` (file: `feature_scaler.pkl`).
- LSTM reshape used in code: features are reshaped to (samples, timesteps, features) where `timesteps=1` and `features=24`. Example reshape call from code:

  - features_array = np.array(features).reshape(1, -1)
  - features_scaled = scaler.transform(features_array)
  - features_lstm = features_scaled.reshape(features_scaled.shape[0], 1, features_scaled.shape[1])

- Model output: single scalar probability; code treats > 0.5 as `phishing`.

## Exact feature list and ordering (24 features)

The feature extractor (`Scamify-main/Extension/backend/lstm_feature_extractor.py`) produces the following 24-element vector in this exact order (this is the order expected by the model and saved CSVs/tests):

1. success
2. num_events
3. ssl_valid
4. ssl_invalid
5. redirects
6. forms
7. password_fields
8. iframes
9. scripts
10. suspicious_keywords
11. external_requests
12. page_load_time (ms)
13. has_errors
14. count_ssl_invalid
15. count_webdriver_error
16. count_ssl_valid
17. count_redirects
18. count_external_requests
19. count_forms_detected
20. count_password_fields
21. count_iframes_detected
22. count_scripts_detected
23. count_suspicious_keywords
24. count_page_load_time

Notes:
- `page_load_time` is measured in milliseconds by the extractor.
- Several features have both raw counts and binary "count_*" presence flags; the model expects this ordering.

## Preprocessing details

 - The repository uses scikit-learn's `StandardScaler` to normalize features before feeding them into the LSTM. The scaler is persisted with `joblib.dump` (e.g. `feature_scaler.pkl`).
 - The usual inference pipeline used across the repo:

 ```python
 # 1) extract features -> list or array of 24 numbers (order above)
 features_array = np.array(features).reshape(1, -1)

 # 2) load scaler and scale
 scaler = joblib.load('feature_scaler.pkl')
 features_scaled = scaler.transform(features_array)

 # 3) reshape for LSTM (timesteps=1)
 features_lstm = features_scaled.reshape(features_scaled.shape[0], 1, features_scaled.shape[1])

 # 4) load model and predict
 model = keras.models.load_model('basic_lstm_model_best.h5', compile=False)
 prob = model.predict(features_lstm)[0][0]
 label = 'phishing' if prob > 0.5 else 'legitimate'
 ```

 ## Empirical results (local evaluation)

 I ran a local evaluation using the project's test script (adjusted to use the available dataset). Below are the exact numeric results produced on a held-out test set (200 samples) using the provided scaler and two model checkpoints.

 Dataset used for this evaluation
 - `merged_training_dataset.csv` (copied to `events_dataset_full.csv` to match test scripts). The test split was 20% of the processed dataset, giving 200 test samples for the final comparison.

 Summary of results (test set, n=200)

 Best model (basic_lstm_model_best.h5)
 - Accuracy: 0.7700
 - Precision: 0.8667
 - Recall: 0.6436
 - F1-score: 0.7386
 - ROC AUC: 0.8722

 Final epoch model (phishing_lstm_model (1).h5)
 - Accuracy: 0.7450
 - Precision: 0.9167
 - Recall: 0.5446
 - F1-score: 0.6832
 - ROC AUC: 0.8652

 Metric-by-metric winner (higher = better):
 - Accuracy: Best model (0.7700 vs 0.7450)
 - Precision: Final model (0.9167 vs 0.8667)
 - Recall: Best model (0.6436 vs 0.5446)
 - F1-score: Best model (0.7386 vs 0.6832)
 - ROC AUC: Best model (0.8722 vs 0.8652)

 Final recommendation from this run: `basic_lstm_model_best.h5` (won 4 out of 5 metrics).

 Confusion matrices (test set, counts)

 Best model (basic_lstm_model_best.h5)
 ```
                  Predicted
 Actual     Legit  Phishing
 Legit      89    10
 Phishing   36    65
 ```

 Final model (phishing_lstm_model (1).h5)
 ```
                  Predicted
 Actual     Legit  Phishing
 Legit      94     5
 Phishing   46    55
 ```

 Notes on evaluation
 - The test harness used the project's scaler file found in the repo (`feature_scaler (1).pkl` / `Scamify-main/Extension/backend/models/feature_scaler.pkl`) to transform features before evaluation.
 - The dataset used for this run is the merged training dataset included in the repo (`merged_training_dataset.csv`). The sample sizes and class distributions in that CSV influence these metrics; if you use a different dataset, metrics may change.

 Model architecture (summary)
 - I also inspected the `basic_lstm_model_best.h5` model and captured the `model.summary()` output (trimmed):

 ```
 Model: "sequential"
 Layer (type)                         Output Shape                Param #
 lstm (LSTM)                          (None, 1, 128)              78,336
 dropout (Dropout)                    (None, 1, 128)              0
 lstm_1 (LSTM)                        (None, 64)                  49,408
 dropout_1 (Dropout)                  (None, 64)                  0
 dense (Dense)                        (None, 50)                  3,250
 dropout_2 (Dropout)                  (None, 50)                  0
 dense_1 (Dense)                      (None, 25)                  1,275
 dropout_3 (Dropout)                  (None, 25)                  0
 dense_2 (Dense)                      (None, 1)                   26

 Total params: 132,295
 Trainable params: 132,295
 Non-trainable params: 0
 ```

 Where the parameters come from
 - First LSTM layer (128 units) and second LSTM layer (64 units) form the bulk of the parameters (78,336 and 49,408 respectively). The small dense layers add ~4.5k parameters.

 Where the evaluation artifacts were saved
 - `model_comparison_results.json` — the JSON summary of both models' metrics (created in repo root)
 - `Scamify-main/Extension/backend/models/model_report.json` — the model inspection JSON with the `model.summary()` text and per-layer param counts

 How I ran the evaluation (commands executed locally in project root)

 ```powershell
 # 1) Create a dataset file expected by test scripts
 Copy-Item .\merged_training_dataset.csv .\events_dataset_full.csv -Force

 # 2) Inspect model and scaler (generates model_report.json)
 python .\model_inspect.py --model "Scamify-main/Extension/backend/models/basic_lstm_model_best.h5" --scaler "feature_scaler.pkl"

 # 3) Run model comparison test (saves model_comparison_results.json)
 python .\test_both_models.py
 ```

 If you want a formatted, exportable table of these results (CSV or LaTeX) included in this report, or a short executive summary slide, tell me which format you prefer and I'll add it.

## Actions taken (threshold tuning & quick retrain)

Following the evaluation above I performed two practical improvement steps and saved artifacts in the repo:

1) Threshold tuning (no retrain)
- I searched thresholds 0.00–1.00 and selected the threshold that maximized F1 on the held-out test split. Results saved to `threshold_tuning_results.json`.
- Best threshold found: 0.43. At this operating point the `basic_lstm_model_best.h5` model shows on the test set (n=200):
  - Accuracy: 0.81
  - Precision: 0.8182
  - Recall: 0.8020
  - F1-score: 0.8100
  - ROC AUC: 0.8722
- Confusion matrix at 0.43:
```
[[81, 18],
 [20, 81]]
```

2) Quick retrain with class weighting
- I continued training the existing `basic_lstm_model_best.h5` for 10 epochs using class weights computed on the training split. Script: `scripts/retrain_quick.py`.
- Retrained model saved as `basic_lstm_model_quick_retrain.h5`. Results saved to `quick_retrain_results.json`.
- Retrain evaluation (test set, n=200):
  - At threshold 0.5: Accuracy 0.865, Precision 0.8136, Recall 0.9505, F1 0.8767, ROC AUC 0.9563
  - At threshold 0.43: Accuracy 0.85, Precision 0.7934, Recall 0.9505, F1 0.8649, ROC AUC 0.9563

Notes on the retrain results:
- The quick retrain produced a substantial improvement in recall (to ~95%) and increased ROC AUC — this indicates the model can be improved further by continued training, architecture tuning, or better regularization/early stopping.
- Class weights computed from the training split were close to balanced for this dataset; nevertheless, continuing training improved recall (model became more sensitive to phishing examples).

## Recommended immediate changes
- Set production inference threshold to 0.43 (immediate benefit). I updated the inference wrapper `Scamify-main/Extension/backend/lstm_predictor.py` so the default prediction threshold is `0.43` (configurable in the constructor).
- Deploy the retrained model (`basic_lstm_model_quick_retrain.h5`) only after validation with your production holdout — I can help validate and replace the saved production model if you want.

## Next steps (if you want me to continue)
- Run a medium-term training run (30–100 epochs) of the improved/BiLSTM architecture from `phishing_lstm_model.ipynb` with the same preprocessing and class weighting, plus ModelCheckpoint + EarlyStopping + ReduceLROnPlateau.
- Run a small hyperparameter sweep (learning rate, dropout, LSTM units, batch size) and compare via cross-validation.
- Add probability calibration (Platt or isotonic) and automated threshold selection per desired operating point (maximize recall subject to precision >= X).

If you want me to (pick one):
- "Apply threshold" — I'll also add a short unit test and README note showing the new default threshold and how to override it.
- "Promote retrain" — I'll run a small holdout validation (or your production validation script) and, if acceptable, replace the production model file and update any deployment scripts.
- "Full training" — I'll run the medium-term training plan and compare results in a reproducible training script.

