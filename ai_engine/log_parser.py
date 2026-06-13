
import argparse
import logging
import os

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# LogParser
# ---------------------------------------------------------------------------

class LogParser:
    """
    Load CICIDS2017 CSV files, keep only attack traffic, clean invalid
    values, and save one combined output file.

    Parameters
    ----------
    tuesday_csv_path  : path to Tuesday traffic CSV  (SSH / FTP-Patator)
    thursday_csv_path : path to Thursday traffic CSV (Web Attacks)
    friday_csv_path   : path to Friday traffic CSV   (Botnet)
    combined_output_path : destination for combined_attacks.csv
    """

    # Label values used in CICIDS2017
    BENIGN_LABEL       = "BENIGN"
    SSH_LABELS         = ["ftp-patator", "ssh-patator"]
    WEB_ATTACK_LABELS  = ["web attack"]
    BOTNET_LABELS      = ["bot"]

    def __init__(
        self,
        tuesday_csv_path: str = "data/tuesday.csv",
        thursday_csv_path: str = "data/thursday.csv",
        friday_csv_path: str = "data/friday.csv",
        combined_output_path: str = "data/combined_attacks.csv",
    ):
        self.tuesday_csv_path = tuesday_csv_path
        self.thursday_csv_path = thursday_csv_path
        self.friday_csv_path = friday_csv_path
        self.combined_output_path = combined_output_path

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _load_csv(self, csv_path: str) -> pd.DataFrame:
        """
        Load an entire CSV file and normalize headers for reliable filtering.

        Returns an empty DataFrame if the file does not exist.
        """
        if not os.path.exists(csv_path):
            log.warning("File not found, skipping: %s", csv_path)
            return pd.DataFrame()

        log.info("Loading %s …", csv_path)
        df = pd.read_csv(csv_path, low_memory=False)

        # Strip leading/trailing spaces from column names
        df.columns = df.columns.str.strip()

        # Strip spaces from the Label column
        if "Label" in df.columns:
            df["Label"] = df["Label"].astype(str).str.strip()

        log.info("  → %s rows, %s columns", f"{len(df):,}", len(df.columns))
        return df

    def _filter_attack_labels(self, df: pd.DataFrame, substrings: list[str]) -> pd.DataFrame:
        """
        Keep only rows whose Label column matches any attack substring.
        """
        if df.empty or "Label" not in df.columns:
            return pd.DataFrame(columns=df.columns if not df.empty else [])

        label_lower = df["Label"].astype(str).str.lower()
        attack_mask = pd.Series(False, index=df.index)
        for substring in substrings:
            attack_mask |= label_lower.str.contains(substring, na=False)

        return df[attack_mask].copy()

    def _clean(self, df: pd.DataFrame) -> pd.DataFrame:
        """Replace Inf/-Inf with NaN and drop rows containing any missing values."""
        if df.empty:
            return df

        # Treat infinite values as invalid and remove the affected rows.
        df = df.replace([np.inf, -np.inf], np.nan)

        before = len(df)
        df = df.dropna()
        dropped = before - len(df)
        if dropped:
            log.info("  Dropped %s rows with Inf/NaN values.", f"{dropped:,}")

        return df.reset_index(drop=True)

    def _print_distribution(self, df: pd.DataFrame, title: str) -> None:
        """Print label distribution as a tidy table for quick inspection."""
        if df.empty or "Label" not in df.columns:
            return
        counts = df["Label"].value_counts()
        log.info("--- %s ---", title)
        for label, count in counts.items():
            pct = 100 * count / len(df)
            log.info("  %-40s %8s  (%5.1f%%)", label, f"{count:,}", pct)

    def _ensure_dir(self, path: str) -> None:
        """Create parent directory of a file path if it does not exist."""
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)

    def _save(self, df: pd.DataFrame, path: str, label: str) -> None:
        """Save a DataFrame to CSV and log the result."""
        self._ensure_dir(path)
        df.to_csv(path, index=False)
        log.info("Saved %s → %s  (%s rows)", label, path, f"{len(df):,}")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build_attack_dataset(self) -> pd.DataFrame:
        """
        Full pipeline: load all source files, keep only attack rows, add a
        sampled BENIGN subset from Tuesday, clean invalid values, and save a
        single combined CSV.
        """
        log.info("=" * 60)
        log.info("Step 1/4  Loading source files")
        log.info("=" * 60)

        tuesday_df = self._load_csv(self.tuesday_csv_path)
        thursday_df = self._load_csv(self.thursday_csv_path)
        friday_df = self._load_csv(self.friday_csv_path)

        # Combine the source files first so the cleaning step runs once.
        combined_raw = pd.concat([tuesday_df, thursday_df, friday_df], ignore_index=True)

        # ------------------------------------------------------------------
        log.info("=" * 60)
        log.info("Step 2/4  Filtering attack labels")
        log.info("=" * 60)

        attack_rows = self._filter_attack_labels(
            combined_raw,
            self.SSH_LABELS + self.WEB_ATTACK_LABELS + self.BOTNET_LABELS,
        )

        # Pull a small BENIGN sample from Tuesday to keep the dataset mixed
        # without oversampling or class balancing.
        benign_rows = tuesday_df.copy()
        if "Label" in benign_rows.columns:
            benign_rows["Label"] = benign_rows["Label"].astype(str).str.strip()
            benign_rows = benign_rows[
                benign_rows["Label"].str.upper() == self.BENIGN_LABEL
            ].copy()
            if not benign_rows.empty:
                benign_rows = benign_rows.sample(
                    n=min(2000, len(benign_rows)),
                    random_state=42,
                )
                # Keep the BENIGN label explicit even after sampling.
                benign_rows["Label"] = self.BENIGN_LABEL
        else:
            benign_rows = pd.DataFrame(columns=tuesday_df.columns)

        # Combine attack rows with the sampled BENIGN rows before cleaning.
        combined_rows = pd.concat([attack_rows, benign_rows], ignore_index=True)

        self._print_distribution(attack_rows, "Attack rows (raw)")
        self._print_distribution(benign_rows, "BENIGN rows (sampled from Tuesday)")

        # ------------------------------------------------------------------
        log.info("=" * 60)
        log.info("Step 3/4  Cleaning invalid values")
        log.info("=" * 60)

        combined_clean = self._clean(combined_rows)

        self._print_distribution(combined_clean, "Combined rows (cleaned)")

        # ------------------------------------------------------------------
        log.info("=" * 60)
        log.info("Step 4/4  Saving combined output")
        log.info("=" * 60)

        self._save(combined_clean, self.combined_output_path, "Combined attacks")

        log.info("=" * 60)
        log.info("Pipeline complete.")
        log.info("  combined_attacks.csv → %s rows", f"{len(combined_clean):,}")
        log.info("=" * 60)

        return combined_clean

    def get_feature_columns(self, df: pd.DataFrame) -> list:
        """Return numeric feature column names (excludes Label)."""
        return [
            c for c in df.columns
            if c != "Label" and pd.api.types.is_numeric_dtype(df[c])
        ]

    def summary(self, df: pd.DataFrame, name: str = "Dataset") -> None:
        """Print a short summary: shape, label distribution, NaN count."""
        log.info("--- Summary: %s ---", name)
        log.info("  Shape : %s rows × %s cols", f"{df.shape[0]:,}", df.shape[1])
        if "Label" in df.columns:
            self._print_distribution(df, name)
        nan_count = df.isnull().sum().sum()
        log.info("  NaN   : %s", f"{nan_count:,}")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Build a cleaned combined attack dataset from CICIDS2017 CSV files."
    )
    p.add_argument("--tuesday", default="data/tuesday.csv", help="Path to Tuesday CSV")
    p.add_argument("--thursday", default="data/thursday.csv", help="Path to Thursday CSV")
    p.add_argument("--friday", default="data/friday.csv", help="Path to Friday CSV")
    p.add_argument("--combined", default="data/combined_attacks.csv", help="Output: combined CSV")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()

    parser = LogParser(
        tuesday_csv_path=args.tuesday,
        thursday_csv_path=args.thursday,
        friday_csv_path=args.friday,
        combined_output_path=args.combined,
    )

    parser.build_attack_dataset()