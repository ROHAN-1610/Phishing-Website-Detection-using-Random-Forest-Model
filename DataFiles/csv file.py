import pandas as pd

# Read the CSV file into a DataFrame
df = pd.read_csv("dataset_phishing.csv")

# Function to remove prefixes from URLs
def remove_prefix(url):
    prefixes = ["http://", "https://", "http://www.","https://www."]
    for prefix in prefixes:
        if url.startswith(prefix):
            return url[len(prefix):]
    return url

# Apply the function to the 'url' column
df['url'] = df['url'].apply(remove_prefix)

# Save the modified DataFrame to a new CSV file
df.to_csv("modified_file.csv", index=False)
