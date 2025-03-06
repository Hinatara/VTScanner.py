
```markdown
# VirusTotal Checker Utility

This utility was created out of a spontaneous need to avoid the hassle of manually uploading files or URLs to VirusTotal for checking. By writing this script, I not only practiced my coding skills but also solved a personal problem.

You can refer to the documentation at [VirusTotal Python API](https://github.com/VirusTotal/vt-py), which I used as a reference while developing this script.

## Instructions:

1. **Install the required package:**
   '''bash 
   pip install vt-py
   ```

2. **Clone the repository:**
   ```bash
   git clone https://github.com/Hinatara/VTScanner.py.git
   ```

3. **Navigate to the project directory:**
   ```bash
   cd VTScanner.py
   ```

4. **Run the script:**
   ```bash
   python virustotal-checker.py
   ```

---

**Note:** The first time you run the script, it will prompt you to enter your VirusTotal API key. This key will be saved in a `config.json` file, so you won't need to enter it again in subsequent runs. If you want to verify the saved API key, you can use the command:
```bash
cat config.json
```

---

If you encounter any issues, please report them at [VTScanner Issues](https://github.com/Hinatara/VTScanner.py/issues), and I will address them as soon as possible.
```
