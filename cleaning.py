from google.colab import files
import pandas as pd
import io

# Upload file
uploaded = files.upload()

# Load CSV
df = pd.read_csv(io.BytesIO(list(uploaded.values())[0]), on_bad_lines='skip')
print(df.shape)
print(df.columns.tolist())

# Fix encoding issues in Description column
df['Description'] = df['Description'].astype(str).str.replace('\n', ' ', regex=False)
df['Description'] = df['Description'].str.replace('\r', ' ', regex=False)
df['Description'] = df['Description'].str.replace('"', "'", regex=False)

# Export clean file
df.to_csv('healthcare_clean.csv', index=False, quoting=1)
files.download('healthcare_clean.csv')
print("✅ Clean file exported!")
