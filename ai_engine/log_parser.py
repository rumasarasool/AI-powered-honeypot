import os
import pandas as pd


class LogParser:
    def __init__(
        self,
        tuesday_csv_path="data/tuesday.csv",
        thursday_csv_path="data/thursday.csv",
        friday_csv_path="data/friday.csv",
        ssh_output_path="data/ssh_attacks.csv",
        http_output_path="data/http_attacks.csv",
    ):
        # Step 1: Store all file paths used by the parser.
        self.tuesday_csv_path = tuesday_csv_path
        self.thursday_csv_path = thursday_csv_path
        self.friday_csv_path = friday_csv_path
        self.ssh_output_path = ssh_output_path
        self.http_output_path = http_output_path

    def _load_csv_sample(self, csv_path, nrows=50000):
        """Load a capped sample of a CSV file."""
        # Step 1: Exit early if the CSV file does not exist.
        if not os.path.exists(csv_path):
            return pd.DataFrame()

        # Step 2: Load only the requested number of rows to limit memory usage.
        return pd.read_csv(csv_path, nrows=nrows)

    def _filter_label_contains(self, df, label_substring):
        """Filter rows that contain a substring in the Label column."""
        # Step 1: Return an empty DataFrame if input data is missing.
        if df.empty:
            return pd.DataFrame(columns=df.columns)

        # Step 2: Return empty if the required column is absent.
        if "Label" not in df.columns:
            return pd.DataFrame(columns=df.columns)

        # Step 3: Apply a case-insensitive filter on the Label column.
        return df[
            df["Label"].astype(str).str.contains(label_substring, case=False, na=False)
        ].copy()

    def build_attack_datasets(self, nrows=50000):
        """Create and save SSH, HTTP, and botnet datasets."""
        # Step 1: Load 50,000-row samples from each day.
        tuesday_df = self._load_csv_sample(self.tuesday_csv_path, nrows=nrows)
        thursday_df = self._load_csv_sample(self.thursday_csv_path, nrows=nrows)
        friday_df = self._load_csv_sample(self.friday_csv_path, nrows=nrows)

        # Step 2: Filter Tuesday rows for FTP-Patator (SSH pipeline).
        ssh_tuesday_df = self._filter_label_contains(tuesday_df, "FTP-Patator")

        # Step 3: Filter Thursday rows for Web Attack (HTTP pipeline).
        http_thursday_df = self._filter_label_contains(thursday_df, "Web Attack")

        # Step 4: Filter Friday rows for Botnet (botnet pipeline).
        botnet_friday_df = self._filter_label_contains(friday_df, "Botnet")

        # Step 5: Combine SSH-related rows (Tuesday FTP-Patator + Friday Botnet).
        ssh_attacks_df = pd.concat([ssh_tuesday_df, botnet_friday_df], ignore_index=True)

        # Step 6: Ensure the output directories exist.
        ssh_output_dir = os.path.dirname(self.ssh_output_path)
        if ssh_output_dir:
            os.makedirs(ssh_output_dir, exist_ok=True)

        http_output_dir = os.path.dirname(self.http_output_path)
        if http_output_dir:
            os.makedirs(http_output_dir, exist_ok=True)

        # Step 7: Save the SSH and HTTP datasets to CSV.
        ssh_attacks_df.to_csv(self.ssh_output_path, index=False)
        http_thursday_df.to_csv(self.http_output_path, index=False)

        # Step 8: Print counts for each pipeline output.
        print(f"SSH attacks found: {len(ssh_attacks_df)}")
        print(f"Web attacks found: {len(http_thursday_df)}")
        print(f"Botnet rows found: {len(botnet_friday_df)}")

        # Step 9: Return dataframes for downstream use if needed.
        return ssh_attacks_df, http_thursday_df, botnet_friday_df


if __name__ == "__main__":
    # Step 1: Create the log parser with default paths.
    parser = LogParser()

    # Step 2: Run the full pipeline and persist outputs to CSV.
    parser.build_attack_datasets(nrows=50000)
