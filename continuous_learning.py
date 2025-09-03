import json
import os
from transformers import AutoModelForSequenceClassification, Trainer, TrainingArguments
from huggingface_hub import snapshot_download

MODEL_PATH = "models/models--microsoft--codebert-base"

def store_feedback(finding_id, user_feedback):
    os.makedirs("learning_data", exist_ok=True)
    with open(f"learning_data/{finding_id}.json", "w") as f:
        json.dump(user_feedback, f)

def retrain_ml_model():
    # Load data from learning_data
    dataset = []  # Load feedbacks as labeled data
    model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH)
    training_args = TrainingArguments(output_dir="models/trained", num_train_epochs=3)
    trainer = Trainer(model=model, args=training_args, train_dataset=dataset)
    trainer.train()
    model.save_pretrained(MODEL_PATH)

# Call retrain periodically or on feedback threshold
