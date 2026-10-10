import os

files = [
    r"c:\Users\Ameena Nazneen\Desktop\final project\backend\error.log",
    r"c:\Users\Ameena Nazneen\Desktop\final project\backend\auth_debug.log"
]

with open("debug_out.txt", "w", encoding="utf-8") as out:
    for file_path in files:
        if os.path.exists(file_path):
            out.write(f"\n========== {os.path.basename(file_path)} ==========\n")
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    content = f.read()
                    out.write(content[-3000:] if len(content) > 3000 else content)
            except UnicodeDecodeError:
                out.write("Retrying with utf-16le...\n")
                with open(file_path, "r", encoding="utf-16le") as f:
                    content = f.read()
                    out.write(content[-3000:] if len(content) > 3000 else content)
