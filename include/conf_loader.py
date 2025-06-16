import os, tomllib

__all__ = ["global_config"]

# include/conf_loader.py

# This module loads the global configuration from a TOML file.
# It is intended to be imported by other modules to access the configuration settings.
# Load the global configuration from a TOML file.

# Ensure that the file is read in binary mode for compatibility with tomllib

if __name__ == "__main__":
    raise RuntimeError("This module should not be run directly.")

if not os.path.exists("config.toml"):
    raise FileNotFoundError("Configuration file 'config.toml' not found.")

with open("config.toml", "rb") as f:
    global_config = tomllib.load(f)
