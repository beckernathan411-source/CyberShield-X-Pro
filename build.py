import os
import subprocess
import sys

def create_installer():
    script_name = "main.py"
    app_name = "CyberShield_X_Pro"
    
    if not os.path.exists(script_name):
        print(f"Erreur : Le fichier {script_name} est introuvable.")
        sys.exit(1)

    print(f"Compilation de {app_name} en cours...")
    
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--onefile",
        "--windowed",
        f"--name={app_name}",
        script_name
    ]
    
    try:
        subprocess.run(command, check=True)
        print("\n==================================================")
        print("🎉 Compilation réussie !")
        print(f"Ton installateur prêt à l'emploi se trouve dans le dossier : dist/{app_name}.exe")
        print("==================================================")
    except subprocess.CalledProcessError:
        print("Erreur lors de la compilation avec PyInstaller.")

if __name__ == "__main__":
    create_installer()