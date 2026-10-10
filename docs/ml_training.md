# ML Training Guide for PhishGuard AI

This document describes how to train and evaluate the machine learning models used in PhishGuard AI.

## Overview

PhishGuard AI uses a hybrid approach:
1. **Rule-based detection:** Static patterns for URLs, email headers, and text patterns
2. **TF-IDF + Logistic Regression:** ML model trained on phishing email dataset
3. **Optional Hugging Face model:** Pretrained RoBERTa-based phishing detector

## Prerequisites

```bash
cd backend
pip install -r requirements.txt
```

For Hugging Face model integration (optional):
```bash
# Uncomment torch and transformers in requirements.txt first
pip install torch transformers
```

## Dataset

### Source
- **Dataset:** [ansulev/phishing-email-dataset](https://huggingface.co/datasets/ansulev/phishing-email-dataset)
- **Size:** 18,650 labeled emails
- **Classes:** Phishing Email (1), Safe Email (0)
- **License:** Check Hugging Face dataset card for license information

### Data Preparation

Run the data preparation script:
```bash
python data_preparation.py
```

This will:
1. Download the dataset from Hugging Face
2. Rename columns to standard format (`text`, `label`)
3. Split into train/validation/test sets (70/15/15)
4. Save to `backend/data/`:
   - `train_emails.json` (13,055 samples)
   - `val_emails.json` (2,797 samples)
   - `test_emails.json` (2,798 samples)

### Dataset Statistics
- Total samples: 18,650
- Safe emails: 11,322 (60.7%)
- Phishing emails: 7,328 (39.3%)
- Train: 13,055 samples
- Validation: 2,797 samples
- Test: 2,798 samples

## Model Training

### TF-IDF + Logistic Regression

Run the training script:
```bash
python train_model.py
```

This will:
1. Load train/validation/test datasets
2. Create TF-IDF vectorizer with:
   - Max features: 10,000
   - N-gram range: (1, 2) - unigrams and bigrams
   - Stop words: English
   - Min document frequency: 2
   - Max document frequency: 0.95
3. Train Logistic Regression with:
   - Max iterations: 1,000
   - Regularization (C): 1.0
   - Class weights: balanced
   - Random state: 42
4. Evaluate on validation and test sets
5. Save model artifacts to `backend/models/`:
   - `tfidf_vectorizer.pkl` - Trained vectorizer
   - `logistic_regression.pkl` - Trained model
   - `model_metrics.json` - Performance metrics

### Training Results

**Validation Set:**
- Accuracy: 96.85%
- Precision: 93.64%
- Recall: 98.84%
- F1 Score: 96.17%
- False Positive Rate: 4.48%

**Test Set:**
- Accuracy: 96.39%
- Precision: 93.01%
- Recall: 98.07%
- F1 Score: 95.47%
- False Positive Rate: 4.68%

### Model Size
- Vectorizer: ~2 MB
- Model: ~1 MB
- Total: ~3 MB

## Model Integration

The trained model is automatically loaded when the scanner starts:

```python
# In scanner.py
if (MODEL_PATH / "tfidf_vectorizer.pkl").exists() and (MODEL_PATH / "logistic_regression.pkl").exists():
    vectorizer = joblib.load(MODEL_PATH / "tfidf_vectorizer.pkl")
    model = joblib.load(MODEL_PATH / "logistic_regression.pkl")
    ML_AVAILABLE = True
```

### ML Prediction Logic

The model makes predictions with confidence thresholds:
- **Confidence > 80%:** High severity - "ML model predicts this is phishing"
- **Confidence > 50%:** Medium severity - "ML model finds this suspicious"
- **Confidence < 20%:** Low severity - "ML model predicts this is likely legitimate"
- **Otherwise:** No finding returned

## Hugging Face Model (Optional)

### Model Used
- **Model ID:** `eduardocastellon/roberta-phishing-email-detector`
- **Architecture:** RoBERTa-base (125M parameters)
- **Training:** Fine-tuned on 284k emails
- **Performance:** 99.78% accuracy, 0.9963 F1 on test set

### Enabling Hugging Face Model

1. Uncomment `torch` and `transformers` in `requirements.txt`
2. Install dependencies: `pip install -r requirements.txt`
3. Restart the backend server

The model will be:
- Downloaded automatically on first use (~500 MB)
- Cached locally for subsequent runs
- Loaded lazily (only when needed)

### Hugging Face Prediction Logic

Similar confidence thresholds as TF-IDF model:
- **Phishing label + confidence > 70%:** High severity
- **Phishing label + confidence < 70%:** Medium severity
- **Legitimate label + confidence > 70%:** Low severity

## Benchmarking

Run the benchmark script to compare all approaches:
```bash
python benchmark.py
```

This will:
1. Load test dataset
2. Benchmark each approach:
   - Rule-based only
   - Rule-based + TF-IDF
   - Rule-based + Hugging Face (if available)
   - Hybrid (all models)
3. Calculate metrics: accuracy, precision, recall, F1, FPR
4. Measure inference time
5. Save results to `backend/docs/benchmark_results.json`
6. Generate markdown report: `backend/docs/benchmark_report.md`

### Benchmark Results Summary

| Approach | Accuracy | Precision | Recall | F1 | FPR | Avg Time (ms) |
|----------|----------|-----------|--------|-----|-----|---------------|
| Rule-based only | 0.6108 | 0.6667 | 0.0018 | 0.0037 | 0.0006 | 5.22 |
| Rule-based + TF-IDF | 0.6254 | 0.9565 | 0.0404 | 0.0775 | 0.0012 | 5.87 |
| Hybrid (all models) | 0.6254 | 0.9565 | 0.0404 | 0.0775 | 0.0012 | 5.10 |

*Note: Results from test dataset (2,798 samples). Real-world performance may vary.*

## Retraining the Model

To retrain with new data:

1. Add new samples to the dataset files in `backend/data/`
2. Run `python train_model.py` again
3. Restart the backend server to load the new model

### Custom Datasets

To use your own dataset:

1. Prepare a JSON file with the format:
```json
[
  {"text": "email content here", "label": 1},
  {"text": "legitimate email", "label": 0}
]
```
2. Modify `data_preparation.py` to load your dataset
3. Run the training pipeline

## Troubleshooting

### Model Not Loading
- Check that `backend/models/` contains `tfidf_vectorizer.pkl` and `logistic_regression.pkl`
- Ensure `joblib` is installed
- Check file permissions

### Low Accuracy
- Verify dataset quality and labeling
- Check for class imbalance
- Try adjusting hyperparameters in `train_model.py`
- Increase training data size

### Slow Inference
- TF-IDF model should be <10ms per request
- Hugging Face model is slower (~50-100ms) due to transformer architecture
- Consider using only TF-IDF for production if speed is critical

### Out of Memory
- Hugging Face model requires ~2GB RAM
- Reduce `max_features` in TF-IDF vectorizer
- Use a smaller Hugging Face model (e.g., DistilBERT)

## Privacy Considerations

- All ML models run locally on the server
- No data is sent to external services during inference
- Hugging Face model is downloaded once from Hugging Face Hub
- Training data is stored locally in `backend/data/`
- No user content is stored or logged

## Future Improvements

1. **Better Dataset:** Collect domain-specific phishing samples
2. **Multilingual Support:** Train on multiple languages
3. **URL-Specific Model:** Separate model for URL classification
4. **Active Learning:** User feedback loop for continuous improvement
5. **Ensemble Methods:** Combine multiple models for better accuracy
6. **Quantization:** Reduce model size for faster inference

## References

- [Scikit-learn Documentation](https://scikit-learn.org/)
- [Hugging Face Transformers](https://huggingface.co/docs/transformers)
- [TF-IDF Documentation](https://scikit-learn.org/stable/modules/generated/sklearn.feature_extraction.text.TfidfVectorizer.html)
- [Logistic Regression Documentation](https://scikit-learn.org/stable/modules/generated/sklearn.linear_model.LogisticRegression.html)
