# Step 4 – Select Top 10 Features & Scale Data for ANN

from sklearn.preprocessing import StandardScaler
import pandas as pd

# Keep only top 10 features + target column
top_features = [
    'url_length',
    'average_subdomain_length',
    'entropy_of_url',
    'entropy_of_domain',
    'domain_length',
    'number_of_subdomains',
    'number_of_special_char_in_url',
    'number_of_digits_in_url',
    'number_of_digits_in_domain',
    'number_of_slash_in_url'
]

X = df[top_features]
y = df['Type']  # Target

# Train-test split (same ratio as before)
from sklearn.model_selection import train_test_split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Scale the features
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("Training set shape:", X_train_scaled.shape)
print("Test set shape:", X_test_scaled.shape)
