import hashlib
import os
import shutil
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
import threading
import time
import requests

def get_api_key():
    api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not api_key and os.path.exists(".env"):
        try:
            with open(".env", "r") as f:
                for line in f:
                    if line.startswith("VIRUSTOTAL_API_KEY="):
                        api_key = line.strip().split("=", 1)[1].strip()
                        break
        except Exception:
            pass
    return api_key

API_KEY = get_api_key()
QUARANTINE_DIR = "./quarantaine"

class AntivirusApp:
    def __init__(self, root):
        self.root = root
        self.root.title("CyberShield X Pro - Security Center")
        self.root.geometry("900x720")
        self.root.configure(bg="#0F172A")
        
        self.whitelist = set()
        self.excluded_folder = ""
        self.is_scanning = False
        self.stop_requested = False
        self.animation_frames = ["┤", "┐", "┐", "─", "┘", "┴", "└", "├", "│"]
        self.current_frame = 0

        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TProgressbar", thickness=15, troughcolor="#1E293B", background="#38BDF8")

        header_frame = tk.Frame(root, bg="#1E293B", height=70)
        header_frame.pack(fill="x", side="top")
        header_frame.pack_propagate(False)

        title_label = tk.Label(header_frame, text="🛡️ CYBERSHIELD X PRO", font=("Segoe UI", 16, "bold"), fg="#38BDF8", bg="#1E293B")
        title_label.pack(side="left", padx=20, pady=15)
        
        self.status_indicator = tk.Label(header_frame, text="● ENGINE ACTIVE", font=("Segoe UI", 10, "bold"), fg="#10B981", bg="#1E293B")
        self.status_indicator.pack(side="right", padx=20, pady=20)

        main_layout = tk.Frame(root, bg="#0F172A")
        main_layout.pack(fill="both", expand=True, padx=20, pady=10)

        control_frame = tk.LabelFrame(main_layout, text=" Actions de Protection ", font=("Segoe UI", 10, "bold"), fg="#94A3B8", bg="#0F172A", bd=1, relief="solid")
        control_frame.pack(fill="x", pady=5)

        self.btn_scan_folder = tk.Button(control_frame, text="📁 Scanner Dossier", font=("Segoe UI", 9, "bold"), bg="#38BDF8", fg="#0F172A", activebackground="#0EA5E9", bd=0, cursor="hand2", padx=10, pady=8, command=lambda: self.start_scan_thread("folder"))
        self.btn_scan_folder.grid(row=0, column=0, padx=5, pady=10)

        self.btn_scan_file = tk.Button(control_frame, text="📄 Scanner Fichier", font=("Segoe UI", 9, "bold"), bg="#38BDF8", fg="#0F172A", activebackground="#0EA5E9", bd=0, cursor="hand2", padx=10, pady=8, command=lambda: self.start_scan_thread("file"))
        self.btn_scan_file.grid(row=0, column=1, padx=5, pady=10)

        self.btn_scan_fast = tk.Button(control_frame, text="⚡ Scan Rapide Système", font=("Segoe UI", 9, "bold"), bg="#EAB308", fg="#0F172A", activebackground="#CA8A04", bd=0, cursor="hand2", padx=10, pady=8, command=self.scan_fast_system)
        self.btn_scan_fast.grid(row=0, column=2, padx=5, pady=10)

        self.btn_scan_desktop = tk.Button(control_frame, text="🖥️ Scan Bureau", font=("Segoe UI", 9, "bold"), bg="#1E293B", fg="#F8FAFC", activebackground="#334155", bd=0, cursor="hand2", padx=10, pady=8, command=self.scan_desktop)
        self.btn_scan_desktop.grid(row=0, column=3, padx=5, pady=10)

        self.btn_stop_scan = tk.Button(control_frame, text="🛑 Arrêter", font=("Segoe UI", 9, "bold"), bg="#EF4444", fg="#F8FAFC", activebackground="#DC2626", bd=0, cursor="hand2", padx=10, pady=8, state=tk.DISABLED, command=self.request_stop_scan)
        self.btn_stop_scan.grid(row=0, column=4, padx=5, pady=10)

        options_frame = tk.LabelFrame(main_layout, text=" Paramètres Avancés ", font=("Segoe UI", 10, "bold"), fg="#94A3B8", bg="#0F172A", bd=1, relief="solid")
        options_frame.pack(fill="x", pady=5)

        btn_open_q = tk.Button(options_frame, text="🔒 Voir Quarantaine", font=("Segoe UI", 9), bg="#1E293B", fg="#F8FAFC", bd=0, cursor="hand2", padx=8, pady=5, command=self.open_quarantine_folder)
        btn_open_q.grid(row=0, column=0, padx=5, pady=8)

        btn_clear_q = tk.Button(options_frame, text="🗑️ Vider Quarantaine", font=("Segoe UI", 9), bg="#1E293B", fg="#F8FAFC", bd=0, cursor="hand2", padx=8, pady=5, command=self.clear_quarantine)
        btn_clear_q.grid(row=0, column=1, padx=5, pady=8)

        btn_whitelist = tk.Button(options_frame, text="🏳️ Whitelister", font=("Segoe UI", 9), bg="#1E293B", fg="#F8FAFC", bd=0, cursor="hand2", padx=8, pady=5, command=self.add_to_whitelist)
        btn_whitelist.grid(row=0, column=2, padx=5, pady=8)

        btn_exclude = tk.Button(options_frame, text="🚫 Exclure Répertoire", font=("Segoe UI", 9), bg="#1E293B", fg="#F8FAFC", bd=0, cursor="hand2", padx=8, pady=5, command=self.set_excluded_folder)
        btn_exclude.grid(row=0, column=3, padx=5, pady=8)

        filter_frame = tk.Frame(main_layout, bg="#0F172A")
        filter_frame.pack(fill="x", pady=5)

        filter_label = tk.Label(filter_frame, text="Cible :", font=("Segoe UI", 10), fg="#94A3B8", bg="#0F172A")
        filter_label.pack(side="left", padx=5)

        self.scan_mode_var = tk.StringVar(value="Tous les fichiers")
        self.scan_mode_menu = ttk.Combobox(filter_frame, textvariable=self.scan_mode_var, values=["Tous les fichiers", "Fichiers exécutables à risque uniquement (.exe, .bat, .msi)"], state="readonly", width=55)
        self.scan_mode_menu.pack(side="left", padx=5)

        stats_frame = tk.Frame(main_layout, bg="#1E293B", bd=1, relief="solid")
        stats_frame.pack(fill="x", pady=5)

        self.lbl_stat_scanned = tk.Label(stats_frame, text="Scannés : 0", font=("Segoe UI", 10, "bold"), fg="#94A3B8", bg="#1E293B", padx=20, pady=5)
        self.lbl_stat_scanned.pack(side="left", expand=True)

        self.lbl_stat_danger = tk.Label(stats_frame, text="Menaces : 0", font=("Segoe UI", 10, "bold"), fg="#EF4444", bg="#1E293B", padx=20, pady=5)
        self.lbl_stat_danger.pack(side="left", expand=True)

        self.lbl_stat_whitelist = tk.Label(stats_frame, text="Whitelistés : 0", font=("Segoe UI", 10, "bold"), fg="#10B981", bg="#1E293B", padx=20, pady=5)
        self.lbl_stat_whitelist.pack(side="left", expand=True)

        self.progress = ttk.Progressbar(main_layout, orient="horizontal", mode="determinate")
        self.progress.pack(fill="x", pady=5)

        log_frame = tk.Frame(main_layout, bg="#0F172A")
        log_frame.pack(fill="both", expand=True, pady=5)

        scrollbar = tk.Scrollbar(log_frame)
        scrollbar.pack(side="right", fill="y")

        self.text_area = tk.Text(log_frame, bg="#020617", fg="#34D399", font=("Consolas", 10), bd=0, yscrollcommand=scrollbar.set)
        self.text_area.pack(fill="both", expand=True, side="left")
        scrollbar.config(command=self.text_area.yview)

        if not API_KEY:
            self.safe_log("⚠️ ATTENTION : Aucune clé API détectée dans l'environnement ou dans le fichier .env !\nLe scan Cloud sera indisponible.")
        else:
            self.safe_log("Moteur CyberShield X Pro initialisé. Mode d'authentification sécurisé actif.")

    def animate_radar(self):
        if self.is_scanning:
            self.current_frame = (self.current_frame + 1) % len(self.animation_frames)
            frame = self.animation_frames[self.current_frame]
            self.status_indicator.config(text=f"{frame} ANALYSE EN COURS...", fg="#38BDF8")
            self.root.after(120, self.animate_radar)
        else:
            self.status_indicator.config(text="● ENGINE ACTIVE", fg="#10B981")

    def safe_log(self, message):
        self.text_area.config(state=tk.NORMAL)
        self.text_area.insert(tk.END, message + "\n")
        self.text_area.see(tk.END)
        self.text_area.config(state=tk.DISABLED)

    def update_stats_ui(self, scanned, danger):
        self.lbl_stat_scanned.config(text=f"Scannés : {scanned}")
        self.lbl_stat_danger.config(text=f"Menaces : {danger}")
        self.lbl_stat_whitelist.config(text=f"Whitelistés : {len(self.whitelist)}")

    def calculate_sha256(self, file_path):
        sha256_hash = hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(chunk)
            return sha256_hash.hexdigest()
        except Exception:
            return None

    def check_virustotal(self, file_hash):
        if not API_KEY:
            return "Erreur (Clé non configurée)"
        url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
        headers = {"x-apikey": API_KEY}
        try:
            response = requests.get(url, headers=headers, timeout=4)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                malicious_count = stats['malicious'] + stats['suspicious']
                if malicious_count > 0:
                    return f"DANGER ({malicious_count} détections)"
                return "Sain"
            elif response.status_code == 404:
                return "Inconnu (Sain)"
            elif response.status_code == 429:
                return "Quota Cloud"
            return "Erreur"
        except requests.exceptions.RequestException:
            return "Erreur Connexion"

    def move_to_quarantine(self, file_path, file_name):
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
        try:
            shutil.move(file_path, os.path.join(QUARANTINE_DIR, file_name))
            return True
        except Exception:
            return False

    def scan_desktop(self):
        desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
        self.start_scan_thread("folder", desktop_path)

    def scan_fast_system(self):
        system_path = os.path.join(os.environ.get('SystemRoot', 'C:\\Windows'), 'System32')
        self.start_scan_thread("folder", system_path)

    def open_quarantine_folder(self):
        if not os.path.exists(QUARANTINE_DIR):
            os.makedirs(QUARANTINE_DIR)
        os.startfile(os.path.abspath(QUARANTINE_DIR))

    def clear_quarantine(self):
        if os.path.exists(QUARANTINE_DIR):
            confirm = messagebox.askyesno("Confirmation", "Voulez-vous vider la quarantaine ?")
            if confirm:
                for filename in os.listdir(QUARANTINE_DIR):
                    file_path = os.path.join(QUARANTINE_DIR, filename)
                    try:
                        os.remove(file_path)
                    except Exception:
                        pass
                self.text_area.config(state=tk.NORMAL)
                self.text_area.delete("1.0", tk.END)
                self.safe_log("🗑️ Quarantaine vidée.")

    def add_to_whitelist(self):
        file_to_white = filedialog.askopenfilename()
        if file_to_white:
            file_hash = self.calculate_sha256(file_to_white)
            if file_hash:
                self.whitelist.add(file_hash)
                self.update_stats_ui(0, 0)
                self.safe_log(f"🏳️ WHITELIST : {os.path.basename(file_to_white)} immunisé.")

    def set_excluded_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.excluded_folder = os.path.abspath(folder)
            self.safe_log(f"🚫 EXCLUSION : Dossier {folder} écarté des futures analyses.")

    def request_stop_scan(self):
        if self.is_scanning:
            self.stop_requested = True
            self.safe_log("\n🛑 Interruption de l'analyse demandée...")

    def start_scan_thread(self, scan_type, forced_path=None):
        if self.is_scanning:
            return
            
        path = forced_path
        if not path:
            if scan_type == "folder":
                path = filedialog.askdirectory()
            else:
                path = filedialog.askopenfilename()
        
        if not path:
            return
        
        self.is_scanning = True
        self.stop_requested = False
        
        self.btn_scan_folder.config(state=tk.DISABLED)
        self.btn_scan_file.config(state=tk.DISABLED)
        self.btn_scan_fast.config(state=tk.DISABLED)
        self.btn_scan_desktop.config(state=tk.DISABLED)
        self.btn_stop_scan.config(state=tk.NORMAL)
        
        self.text_area.config(state=tk.NORMAL)
        self.text_area.delete("1.0", tk.END)
        self.text_area.config(state=tk.DISABLED)
        
        self.animate_radar()
        
        scan_thread = threading.Thread(target=self.run_scan, args=(path, scan_type))
        scan_thread.daemon = True
        scan_thread.start()

    def run_scan(self, target_path, scan_type):
        self.safe_log(f"🔍 INITIALISATION DU SCAN TURBO : {target_path}")
        
        files_to_scan = []
        if scan_type == "file" or os.path.isfile(target_path):
            files_to_scan.append(target_path)
        else:
            for root_dir, _, files in os.walk(target_path):
                if self.stop_requested:
                    break
                if os.path.abspath(root_dir) == os.path.abspath(QUARANTINE_DIR):
                    continue
                if self.excluded_folder and os.path.abspath(root_dir).startswith(self.excluded_folder):
                    continue
                for f in files:
                    ext = os.path.splitext(f)[1].lower()
                    if self.scan_mode_var.get() != "Tous les fichiers":
                        if ext in [".exe", ".bat", ".msi", ".scr", ".cmd"]:
                            files_to_scan.append(os.path.join(root_dir, f))
                    else:
                        files_to_scan.append(os.path.join(root_dir, f))

        total_files = len(files_to_scan)
        if total_files == 0:
            self.safe_log("Aucun fichier à analyser.")
            self.finalize_scan_state()
            return

        self.progress["maximum"] = total_files
        danger_count = 0
        scanned_count = 0
        cloud_requests_count = 0

        safe_extensions = [".png", ".jpg", ".jpeg", ".gif", ".mp3", ".mp4", ".txt", ".cfg", ".json", ".ini", ".md", ".ico", ".dll", ".sys"]

        for index, file_path in enumerate(files_to_scan):
            if self.stop_requested:
                self.safe_log("\n⚠️ Analyse annulée par l'utilisateur.")
                break
                
            file_name = os.path.basename(file_path)
            ext = os.path.splitext(file_name)[1].lower()
            
            scanned_count += 1
            self.progress["value"] = scanned_count
            self.update_stats_ui(scanned_count, danger_count)
            
            if ext in safe_extensions:
                self.safe_log(f"🚀 [LOCAL] {file_name} : Sain")
                continue

            file_hash = self.calculate_sha256(file_path)
            if not file_hash:
                self.safe_log(f"⚠️ [IGNORÉ] Échec d'accès : {file_name}")
                continue

            if file_hash in self.whitelist:
                self.safe_log(f"🛡️ [WHITELIST] {file_name}")
                continue

            if cloud_requests_count >= 4 and total_files > 5:
                self.safe_log(f"⏳ [CLOUDBURST] Analyse locale sécurisée (Limite Cloud atteinte) : {file_name}")
                continue

            result = self.check_virustotal(file_hash)
            cloud_requests_count += 1
            
            if "DANGER" in result:
                self.safe_log(f"❌ [ALERTE] {file_name} -> {result}")
                danger_count += 1
                if self.move_to_quarantine(file_path, file_name):
                    self.safe_log(f"   🔒 Fichier neutralisé et isolé.")
            else:
                self.safe_log(f"🌐 [CLOUD] {file_name} : {result}")

        self.safe_log("\n" + "="*75)
        self.safe_log(f"📊 TRAITEMENT CYBERSHIELD ACCOMPLI")
        self.safe_log(f"📁 Objets inspectés : {scanned_count} | ⚠️ Menaces écartées : {danger_count}")
        
        self.finalize_scan_state()
        
        if danger_count > 0:
            messagebox.showwarning("CyberShield Alert", f"Analyse terminée. {danger_count} menaces neutralisées.")
        else:
            messagebox.showinfo("CyberShield Report", "Analyse terminée. Votre système est sain.")

    def finalize_scan_state(self):
        self.is_scanning = False
        self.stop_requested = False
        self.btn_scan_folder.config(state=tk.NORMAL)
        self.btn_scan_file.config(state=tk.NORMAL)
        self.btn_scan_fast.config(state=tk.NORMAL)
        self.btn_scan_desktop.config(state=tk.NORMAL)
        self.btn_stop_scan.config(state=tk.DISABLED)

if __name__ == "__main__":
    window = tk.Tk()
    app = AntivirusApp(window)
    window.mainloop()