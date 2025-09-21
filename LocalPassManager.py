#!/usr/bin/env python3
"""
LocalPassManager - Безопасный локальный менеджер паролей с мастер-паролем
Версия 3.1.0 - Улучшенная портативная версия
"""

import tkinter as tk
from tkinter import messagebox, filedialog, ttk, simpledialog
import json
import os
import hashlib
import secrets
import string
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Настройки приложения
APP_TITLE = "LocalPassManager"
APP_VERSION = "3.1.0"
PASSWORDS_FILE = "passwords.json"
CONFIG_FILE = "config.json"
ICON_FILE = "icon.ico"

# Константы безопасности
PBKDF2_ITERATIONS = 600000
SALT_SIZE = 32
KEY_LENGTH = 32

# Справочная информация
HELP_TEXT = """
LocalPassManager v3.1.0 - Руководство пользователя

МАСТЕР-ПАРОЛЬ:
• При первом запуске создайте надежный мастер-пароль
• Этот пароль будет единственным способом доступа к вашим данным
• ВАЖНО: Запомните или надежно сохраните мастер-пароль!
• Без мастер-пароля восстановить данные НЕВОЗМОЖНО
• Рекомендации: минимум 12 символов, смесь букв, цифр и символов

БЛОКИРОВКА:
• Кнопка "Заблокировать" (Ctrl+L) - блокирует доступ к паролям
• После блокировки требуется повторный ввод мастер-пароля
• Удобно при временном отходе от компьютера

ИМПОРТ/ЭКСПОРТ:
• Экспорт: можно сохранить расшифрованные или зашифрованные данные
• Импорт: можно добавить к текущей базе или заменить полностью
• При импорте зашифрованных данных потребуется мастер-пароль той базы

УПРАВЛЕНИЕ ПАРОЛЯМИ:
• Добавление: Заполните сайт, пользователя, пароль и опционально примечания
• Просмотр: Двойной клик или кнопка "Просмотр"
• Редактирование: F2 или кнопка "Редактировать"
• Удаление: Delete или кнопка "Удалить"
• Поиск: Введите текст для фильтрации

БЕЗОПАСНОСТЬ:
• Все данные шифруются алгоритмом AES-256 (Fernet)
• 600,000 итераций PBKDF2-SHA256
• Локальное хранение без передачи в интернет

ГОРЯЧИЕ КЛАВИШИ:
• Ctrl+G: Генерировать пароль
• Ctrl+A: Добавить запись
• Ctrl+F: Поиск
• Ctrl+E: Экспорт
• Ctrl+M: Сменить мастер-пароль
• Ctrl+L: Заблокировать
• F1: Справка
• F2: Редактировать
• Delete: Удалить
"""


def generate_password(length=12, include_uppercase=True, include_lowercase=True,
                      include_numbers=True, include_symbols=True):
    """Генерирует криптографически стойкий пароль"""
    if not any([include_uppercase, include_lowercase, include_numbers, include_symbols]):
        include_lowercase = True

    chars = ""
    if include_lowercase:
        chars += string.ascii_lowercase
    if include_uppercase:
        chars += string.ascii_uppercase
    if include_numbers:
        chars += string.digits
    if include_symbols:
        chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"

    if not chars:
        chars = string.ascii_lowercase

    return ''.join(secrets.choice(chars) for _ in range(length))


class MasterPasswordDialog:
    """Диалог для создания или ввода мастер-пароля"""

    def __init__(self, parent=None, mode="create", attempts_left=3):
        self.result = None
        self.mode = mode
        self.attempts_left = attempts_left

        if parent is None:
            self.dialog = tk.Tk()
            self.dialog.withdraw()
        else:
            self.dialog = tk.Toplevel(parent)

        self.dialog.title("LocalPassManager - Мастер-пароль")
        self.dialog.resizable(False, False)

        if parent:
            self.dialog.transient(parent)
            self.dialog.grab_set()

        self.dialog.wm_attributes("-topmost", True)

        if os.path.exists(ICON_FILE):
            try:
                self.dialog.iconbitmap(ICON_FILE)
            except:
                pass

        self.setup_ui()
        self.center_window(parent)

        self.dialog.deiconify()
        self.dialog.lift()
        self.dialog.focus_force()

    def setup_ui(self):
        main_frame = tk.Frame(self.dialog, padx=30, pady=25)
        main_frame.pack(fill=tk.BOTH, expand=True)

        if self.mode == "create":
            title = "Создание мастер-пароля"
            description = ("Это ваш первый запуск LocalPassManager.\n"
                           "Создайте надежный мастер-пароль для защиты ваших данных.\n\n"
                           "ВАЖНО: Этот пароль невозможно восстановить!\n"
                           "Обязательно запомните или надежно сохраните его.")
        else:
            title = "Вход в LocalPassManager"
            if self.attempts_left < 3:
                description = f"Введите мастер-пароль для доступа к вашим данным.\n\nОсталось попыток: {self.attempts_left}"
            else:
                description = "Введите мастер-пароль для доступа к вашим данным."

        tk.Label(main_frame, text=title, font=("Segoe UI", 14, "bold")).pack(pady=(0, 15))
        tk.Label(main_frame, text=description, font=("Segoe UI", 10),
                 wraplength=400, justify=tk.LEFT).pack(pady=(0, 20))

        tk.Label(main_frame, text="Мастер-пароль:", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(main_frame, textvariable=self.password_var,
                                       show="*", font=("Segoe UI", 11), width=45)
        self.password_entry.pack(fill=tk.X, pady=(5, 10))
        self.password_entry.focus()

        if self.mode == "create":
            tk.Label(main_frame, text="Подтвердите пароль:", font=("Segoe UI", 10, "bold")).pack(anchor=tk.W)
            self.confirm_var = tk.StringVar()
            self.confirm_entry = tk.Entry(main_frame, textvariable=self.confirm_var,
                                          show="*", font=("Segoe UI", 11), width=45)
            self.confirm_entry.pack(fill=tk.X, pady=(5, 10))

            self.strength_frame = tk.Frame(main_frame)
            self.strength_frame.pack(fill=tk.X, pady=(0, 10))

            tk.Label(self.strength_frame, text="Надежность:", font=("Segoe UI", 9)).pack(side=tk.LEFT)
            self.strength_label = tk.Label(self.strength_frame, text="", font=("Segoe UI", 9, "bold"))
            self.strength_label.pack(side=tk.LEFT, padx=(5, 0))

            self.password_var.trace('w', self.update_strength)

        self.show_var = tk.BooleanVar()
        show_check = tk.Checkbutton(main_frame, text="Показать пароль",
                                    variable=self.show_var, command=self.toggle_password,
                                    font=("Segoe UI", 9))
        show_check.pack(anchor=tk.W, pady=(0, 20))

        buttons_frame = tk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X)

        ok_text = "Создать" if self.mode == "create" else "Войти"
        ok_btn = tk.Button(buttons_frame, text=ok_text, command=self.ok_clicked,
                           bg="#4CAF50", fg="white", font=("Segoe UI", 10, "bold"),
                           padx=30, pady=5)
        ok_btn.pack(side=tk.RIGHT, padx=(10, 0))

        cancel_btn = tk.Button(buttons_frame, text="Отмена", command=self.cancel_clicked,
                               font=("Segoe UI", 10), padx=30, pady=5)
        cancel_btn.pack(side=tk.RIGHT)

        self.dialog.bind('<Return>', lambda e: self.ok_clicked())
        self.dialog.bind('<Escape>', lambda e: self.cancel_clicked())

    def update_strength(self, *args):
        password = self.password_var.get()

        if len(password) == 0:
            self.strength_label.config(text="", fg="black")
        elif len(password) < 8:
            self.strength_label.config(text="Очень слабый", fg="red")
        elif len(password) < 12:
            if any(c.isupper() for c in password) and any(c.isdigit() for c in password):
                self.strength_label.config(text="Средний", fg="orange")
            else:
                self.strength_label.config(text="Слабый", fg="darkorange")
        else:
            complexity = sum([
                any(c.isupper() for c in password),
                any(c.islower() for c in password),
                any(c.isdigit() for c in password),
                any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
            ])
            if complexity >= 3:
                self.strength_label.config(text="Очень надежный", fg="darkgreen")
            else:
                self.strength_label.config(text="Надежный", fg="green")

    def toggle_password(self):
        if self.show_var.get():
            self.password_entry.config(show="")
            if self.mode == "create" and hasattr(self, 'confirm_entry'):
                self.confirm_entry.config(show="")
        else:
            self.password_entry.config(show="*")
            if self.mode == "create" and hasattr(self, 'confirm_entry'):
                self.confirm_entry.config(show="*")

    def center_window(self, parent):
        self.dialog.update_idletasks()
        if parent:
            x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.dialog.winfo_width() // 2)
            y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.dialog.winfo_height() // 2)
        else:
            x = (self.dialog.winfo_screenwidth() // 2) - (self.dialog.winfo_width() // 2)
            y = (self.dialog.winfo_screenheight() // 2) - (self.dialog.winfo_height() // 2)
        self.dialog.geometry(f"+{x}+{y}")

    def ok_clicked(self):
        password = self.password_var.get()

        if not password:
            messagebox.showerror("Ошибка", "Пароль не может быть пустым", parent=self.dialog)
            return

        if self.mode == "create":
            confirm = self.confirm_var.get()
            if password != confirm:
                messagebox.showerror("Ошибка", "Пароли не совпадают", parent=self.dialog)
                return

            if len(password) < 8:
                if not messagebox.askyesno("Предупреждение",
                                           "Пароль слишком короткий (менее 8 символов).\n"
                                           "Это снижает безопасность ваших данных.\n\n"
                                           "Продолжить с этим паролем?", parent=self.dialog):
                    return

        self.result = password
        self.dialog.destroy()

    def cancel_clicked(self):
        self.result = None
        self.dialog.destroy()


class ExportImportDialog:
    """Диалог настроек экспорта/импорта"""

    def __init__(self, parent, mode="export"):
        self.result = None
        self.mode = mode

        self.window = tk.Toplevel(parent)
        self.window.title("Настройки экспорта" if mode == "export" else "Настройки импорта")
        self.window.transient(parent)
        self.window.grab_set()

        self.setup_ui()
        self.center_window(parent)

    def setup_ui(self):
        main_frame = tk.Frame(self.window, padx=25, pady=20)
        main_frame.pack()

        if self.mode == "export":
            tk.Label(main_frame, text="Настройки экспорта",
                     font=("Segoe UI", 12, "bold")).pack(pady=(0, 15))

            self.encrypt_var = tk.BooleanVar(value=True)
            tk.Radiobutton(main_frame, text="Экспортировать зашифрованные данные",
                           variable=self.encrypt_var, value=True,
                           font=("Segoe UI", 10)).pack(anchor=tk.W, pady=5)
            tk.Label(main_frame, text="  (Требуется мастер-пароль для импорта)",
                     font=("Segoe UI", 9), fg="gray").pack(anchor=tk.W, padx=(20, 0))

            tk.Radiobutton(main_frame, text="Экспортировать расшифрованные данные",
                           variable=self.encrypt_var, value=False,
                           font=("Segoe UI", 10)).pack(anchor=tk.W, pady=5)
            tk.Label(main_frame, text="  (⚠️ НЕБЕЗОПАСНО - пароли в открытом виде!)",
                     font=("Segoe UI", 9), fg="red").pack(anchor=tk.W, padx=(20, 0))

        else:  # import
            tk.Label(main_frame, text="Настройки импорта",
                     font=("Segoe UI", 12, "bold")).pack(pady=(0, 15))

            self.mode_var = tk.StringVar(value="add")
            tk.Radiobutton(main_frame, text="Добавить к текущей базе данных",
                           variable=self.mode_var, value="add",
                           font=("Segoe UI", 10)).pack(anchor=tk.W, pady=5)

            tk.Radiobutton(main_frame, text="Заменить текущую базу данных",
                           variable=self.mode_var, value="replace",
                           font=("Segoe UI", 10)).pack(anchor=tk.W, pady=5)
            tk.Label(main_frame, text="  (⚠️ Текущие данные будут удалены!)",
                     font=("Segoe UI", 9), fg="red").pack(anchor=tk.W, padx=(20, 0))

        buttons_frame = tk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(20, 0))

        tk.Button(buttons_frame, text="Продолжить", command=self.ok,
                  bg="#4CAF50", fg="white", padx=20).pack(side=tk.RIGHT, padx=(10, 0))
        tk.Button(buttons_frame, text="Отмена", command=self.cancel,
                  padx=20).pack(side=tk.RIGHT)

    def center_window(self, parent):
        self.window.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.window.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.window.winfo_height() // 2)
        self.window.geometry(f"+{x}+{y}")

    def ok(self):
        if self.mode == "export":
            self.result = {"encrypted": self.encrypt_var.get()}
        else:
            self.result = {"mode": self.mode_var.get()}
        self.window.destroy()

    def cancel(self):
        self.result = None
        self.window.destroy()


class PasswordManager:
    """Менеджер паролей с мастер-паролем"""

    def __init__(self):
        self.key = None
        self.data = {}
        self.config = {}
        self.master_password = None

    def setup_new_database(self, master_password):
        salt = os.urandom(SALT_SIZE)
        self.key = self._derive_key(master_password, salt)
        self.master_password = master_password

        verification_token = "LocalPassManager_V3_Valid"
        encrypted_token = self.encrypt_data(verification_token)

        self.config = {
            "version": "3.1.0",
            "salt": base64.b64encode(salt).decode('utf-8'),
            "iterations": PBKDF2_ITERATIONS,
            "verification": encrypted_token
        }

        self._save_config()
        self.data = {}
        self.save_data()
        return True

    def unlock_database(self, master_password):
        if not self._load_config():
            return False

        salt = base64.b64decode(self.config['salt'])
        self.key = self._derive_key(master_password, salt)
        self.master_password = master_password

        try:
            decrypted_token = self.decrypt_data(self.config['verification'])
            if decrypted_token != "LocalPassManager_V3_Valid":
                return False
        except:
            return False

        return self.load_data()

    def change_master_password(self, new_password):
        if not self.master_password:
            return False

        new_salt = os.urandom(SALT_SIZE)
        new_key = self._derive_key(new_password, new_salt)
        old_key = self.key

        self.key = new_key
        self.master_password = new_password

        verification_token = "LocalPassManager_V3_Valid"
        self.config['salt'] = base64.b64encode(new_salt).decode('utf-8')
        self.config['verification'] = self.encrypt_data(verification_token)

        self._save_config()
        self.save_data()
        return True

    def _derive_key(self, password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_LENGTH,
            salt=salt,
            iterations=PBKDF2_ITERATIONS,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
        return Fernet(key)

    def _save_config(self):
        try:
            with open(CONFIG_FILE, 'w', encoding='utf-8') as f:
                json.dump(self.config, f, indent=2)
            return True
        except Exception as e:
            print(f"Ошибка сохранения конфигурации: {e}")
            return False

    def _load_config(self):
        try:
            if os.path.exists(CONFIG_FILE):
                with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
                return True
            return False
        except Exception as e:
            print(f"Ошибка загрузки конфигурации: {e}")
            return False

    def encrypt_data(self, data):
        if not isinstance(data, str):
            data = str(data)
        return self.key.encrypt(data.encode('utf-8')).decode('utf-8')

    def decrypt_data(self, encrypted_data):
        if not isinstance(encrypted_data, str):
            encrypted_data = str(encrypted_data)
        return self.key.decrypt(encrypted_data.encode('utf-8')).decode('utf-8')

    def save_data(self):
        try:
            encrypted_data = {}
            for site, accounts in self.data.items():
                encrypted_data[site] = {}
                for username, entry in accounts.items():
                    if isinstance(entry, dict):
                        encrypted_data[site][username] = {
                            "password": self.encrypt_data(entry["password"]),
                            "notes": self.encrypt_data(entry.get("notes", ""))
                        }
                    else:
                        encrypted_data[site][username] = {
                            "password": self.encrypt_data(entry),
                            "notes": self.encrypt_data("")
                        }

            with open(PASSWORDS_FILE, 'w', encoding='utf-8') as f:
                json.dump(encrypted_data, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print(f"Ошибка сохранения данных: {e}")
            return False

    def load_data(self):
        if os.path.exists(PASSWORDS_FILE):
            try:
                with open(PASSWORDS_FILE, 'r', encoding='utf-8') as f:
                    encrypted_data = json.load(f)

                self.data = {}
                for site, accounts in encrypted_data.items():
                    self.data[site] = {}
                    for username, entry in accounts.items():
                        try:
                            if isinstance(entry, dict):
                                password = self.decrypt_data(entry["password"])
                                notes = self.decrypt_data(entry.get("notes", ""))
                                self.data[site][username] = {
                                    "password": password,
                                    "notes": notes
                                }
                            else:
                                password = self.decrypt_data(entry)
                                self.data[site][username] = {
                                    "password": password,
                                    "notes": ""
                                }
                        except Exception:
                            return False
                return True
            except Exception as e:
                print(f"Ошибка загрузки данных: {e}")
                return False
        else:
            self.data = {}
            return True

    def add_password(self, site, username, password, notes=""):
        try:
            if site not in self.data:
                self.data[site] = {}

            self.data[site][username] = {
                "password": password,
                "notes": notes
            }
            return self.save_data()
        except Exception as e:
            print(f"Ошибка добавления пароля: {e}")
            return False

    def edit_password(self, old_site, old_username, new_site, new_username, new_password, new_notes=""):
        try:
            if old_site in self.data and old_username in self.data[old_site]:
                del self.data[old_site][old_username]
                if not self.data[old_site]:
                    del self.data[old_site]

            if new_site not in self.data:
                self.data[new_site] = {}

            self.data[new_site][new_username] = {
                "password": new_password,
                "notes": new_notes
            }

            return self.save_data()
        except Exception as e:
            print(f"Ошибка редактирования: {e}")
            return False

    def delete_password(self, site, username):
        try:
            if site in self.data and username in self.data[site]:
                del self.data[site][username]
                if not self.data[site]:
                    del self.data[site]
                return self.save_data()
            return False
        except Exception as e:
            print(f"Ошибка удаления: {e}")
            return False

    def get_password(self, site, username):
        entry = self.data.get(site, {}).get(username)
        if isinstance(entry, dict):
            return entry.get("password", ""), entry.get("notes", "")
        elif isinstance(entry, str):
            return entry, ""
        return None, None

    def search_entries(self, query):
        results = []
        query_lower = query.lower()
        for site, accounts in self.data.items():
            if query_lower in site.lower():
                for username in accounts.keys():
                    results.append((site, username))
            else:
                for username in accounts.keys():
                    if query_lower in username.lower():
                        results.append((site, username))
        return results

    def get_all_entries(self):
        results = []
        for site, accounts in self.data.items():
            for username in accounts.keys():
                results.append((site, username))
        return sorted(results)

    def export_data(self, filepath, encrypted=True):
        try:
            export_data = {
                "version": "3.1.0",
                "encrypted": encrypted
            }

            if encrypted:
                export_data["config"] = self.config
                if os.path.exists(PASSWORDS_FILE):
                    with open(PASSWORDS_FILE, 'r', encoding='utf-8') as f:
                        export_data["passwords"] = json.load(f)
            else:
                # Расшифрованный экспорт
                export_data["passwords"] = {}
                for site, accounts in self.data.items():
                    export_data["passwords"][site] = {}
                    for username, entry in accounts.items():
                        if isinstance(entry, dict):
                            export_data["passwords"][site][username] = {
                                "password": entry["password"],
                                "notes": entry.get("notes", "")
                            }
                        else:
                            export_data["passwords"][site][username] = {
                                "password": entry,
                                "notes": ""
                            }

            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)

            return True
        except Exception as e:
            print(f"Ошибка экспорта: {e}")
            return False

    def import_data(self, filepath, mode="add", import_master_password=None):
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                import_data = json.load(f)

            is_encrypted = import_data.get("encrypted", True)

            if is_encrypted:
                # Импорт зашифрованных данных
                if import_master_password:
                    # Создаем временный менеджер для расшифровки
                    temp_pm = PasswordManager()
                    temp_pm.config = import_data.get("config", {})

                    # Пытаемся разблокировать импортированные данные
                    salt = base64.b64decode(temp_pm.config['salt'])
                    temp_pm.key = temp_pm._derive_key(import_master_password, salt)

                    # Проверяем пароль
                    try:
                        verification = temp_pm.decrypt_data(temp_pm.config['verification'])
                        if verification != "LocalPassManager_V3_Valid":
                            return False
                    except:
                        return False

                    # Расшифровываем данные
                    encrypted_passwords = import_data.get("passwords", {})
                    decrypted_data = {}

                    for site, accounts in encrypted_passwords.items():
                        decrypted_data[site] = {}
                        for username, entry in accounts.items():
                            if isinstance(entry, dict):
                                password = temp_pm.decrypt_data(entry["password"])
                                notes = temp_pm.decrypt_data(entry.get("notes", ""))
                                decrypted_data[site][username] = {
                                    "password": password,
                                    "notes": notes
                                }

                    # Добавляем или заменяем данные
                    if mode == "replace":
                        self.data = decrypted_data
                    else:  # add
                        for site, accounts in decrypted_data.items():
                            if site not in self.data:
                                self.data[site] = {}
                            for username, entry in accounts.items():
                                self.data[site][username] = entry

                    return self.save_data()
                else:
                    return False
            else:
                # Импорт расшифрованных данных
                import_passwords = import_data.get("passwords", {})

                if mode == "replace":
                    self.data = import_passwords
                else:  # add
                    for site, accounts in import_passwords.items():
                        if site not in self.data:
                            self.data[site] = {}
                        for username, entry in accounts.items():
                            if isinstance(entry, dict):
                                self.data[site][username] = entry
                            else:
                                self.data[site][username] = {"password": entry, "notes": ""}

                return self.save_data()

        except Exception as e:
            print(f"Ошибка импорта: {e}")
            return False


class ChangeMasterPasswordDialog:
    """Диалог смены мастер-пароля"""

    def __init__(self, parent, password_manager):
        self.pm = password_manager
        self.result = None

        self.window = tk.Toplevel(parent)
        self.window.title("Смена мастер-пароля")
        self.window.transient(parent)
        self.window.grab_set()

        self.setup_ui()
        self.center_window(parent)

    def setup_ui(self):
        main_frame = tk.Frame(self.window, padx=25, pady=20)
        main_frame.pack()

        tk.Label(main_frame, text="Смена мастер-пароля",
                 font=("Segoe UI", 12, "bold")).pack(pady=(0, 15))

        tk.Label(main_frame, text="Текущий мастер-пароль:",
                 font=("Segoe UI", 10)).pack(anchor=tk.W)
        self.current_var = tk.StringVar()
        self.current_entry = tk.Entry(main_frame, textvariable=self.current_var,
                                      show="*", width=40)
        self.current_entry.pack(fill=tk.X, pady=(5, 15))
        self.current_entry.focus()

        tk.Label(main_frame, text="Новый мастер-пароль:",
                 font=("Segoe UI", 10)).pack(anchor=tk.W)
        self.new_var = tk.StringVar()
        self.new_entry = tk.Entry(main_frame, textvariable=self.new_var,
                                  show="*", width=40)
        self.new_entry.pack(fill=tk.X, pady=(5, 15))

        tk.Label(main_frame, text="Подтвердите новый пароль:",
                 font=("Segoe UI", 10)).pack(anchor=tk.W)
        self.confirm_var = tk.StringVar()
        self.confirm_entry = tk.Entry(main_frame, textvariable=self.confirm_var,
                                      show="*", width=40)
        self.confirm_entry.pack(fill=tk.X, pady=(5, 15))

        self.show_var = tk.BooleanVar()
        tk.Checkbutton(main_frame, text="Показать пароли",
                       variable=self.show_var, command=self.toggle_passwords).pack(anchor=tk.W)

        buttons_frame = tk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X, pady=(20, 0))

        tk.Button(buttons_frame, text="Изменить", command=self.change_password,
                  bg="#4CAF50", fg="white", padx=20).pack(side=tk.RIGHT, padx=(10, 0))
        tk.Button(buttons_frame, text="Отмена", command=self.cancel,
                  padx=20).pack(side=tk.RIGHT)

    def toggle_passwords(self):
        show = "" if self.show_var.get() else "*"
        self.current_entry.config(show=show)
        self.new_entry.config(show=show)
        self.confirm_entry.config(show=show)

    def center_window(self, parent):
        self.window.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.window.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.window.winfo_height() // 2)
        self.window.geometry(f"+{x}+{y}")

    def change_password(self):
        current = self.current_var.get()
        new = self.new_var.get()
        confirm = self.confirm_var.get()

        if current != self.pm.master_password:
            messagebox.showerror("Ошибка", "Неверный текущий пароль", parent=self.window)
            return

        if not new:
            messagebox.showerror("Ошибка", "Новый пароль не может быть пустым", parent=self.window)
            return

        if new != confirm:
            messagebox.showerror("Ошибка", "Новые пароли не совпадают", parent=self.window)
            return

        if len(new) < 8:
            if not messagebox.askyesno("Предупреждение",
                                       "Новый пароль слишком короткий.\nПродолжить?",
                                       parent=self.window):
                return

        if self.pm.change_master_password(new):
            self.result = True
            messagebox.showinfo("Успех", "Мастер-пароль успешно изменен", parent=self.window)
            self.window.destroy()
        else:
            messagebox.showerror("Ошибка", "Не удалось изменить мастер-пароль", parent=self.window)

    def cancel(self):
        self.window.destroy()


class EditPasswordDialog:
    """Диалог редактирования записи"""

    def __init__(self, parent, site, username, password, notes=""):
        self.result = None
        self.window = tk.Toplevel(parent)
        self.window.title("Редактировать пароль")
        self.window.transient(parent)
        self.window.grab_set()

        self.setup_ui(site, username, password, notes)
        self.center_window(parent)

    def setup_ui(self, site, username, password, notes):
        main_frame = tk.Frame(self.window, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)

        tk.Label(main_frame, text="Сайт/Сервис:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        self.site_var = tk.StringVar(value=site)
        tk.Entry(main_frame, textvariable=self.site_var, width=50).pack(fill=tk.X, pady=(2, 12))

        tk.Label(main_frame, text="Имя пользователя/Email:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        self.username_var = tk.StringVar(value=username)
        tk.Entry(main_frame, textvariable=self.username_var, width=50).pack(fill=tk.X, pady=(2, 12))

        tk.Label(main_frame, text="Пароль:", font=("Arial", 10, "bold")).pack(anchor=tk.W)
        self.password_var = tk.StringVar(value=password)
        self.password_entry = tk.Entry(main_frame, textvariable=self.password_var,
                                       show="*", width=50)
        self.password_entry.pack(fill=tk.X, pady=(2, 5))

        self.show_password = tk.BooleanVar()
        tk.Checkbutton(main_frame, text="Показать пароль",
                       variable=self.show_password, command=self.toggle_password).pack(anchor=tk.W, pady=(0, 12))

        tk.Label(main_frame, text="Примечания:", font=("Arial", 10, "bold")).pack(anchor=tk.W)

        notes_frame = tk.Frame(main_frame)
        notes_frame.pack(fill=tk.BOTH, expand=True, pady=(2, 15))

        self.notes_text = tk.Text(notes_frame, height=4, width=50, wrap=tk.WORD)
        scrollbar = tk.Scrollbar(notes_frame, orient=tk.VERTICAL, command=self.notes_text.yview)
        self.notes_text.configure(yscrollcommand=scrollbar.set)

        self.notes_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        if notes:
            self.notes_text.insert(tk.END, notes)

        buttons_frame = tk.Frame(main_frame)
        buttons_frame.pack(fill=tk.X)

        tk.Button(buttons_frame, text="Сохранить", command=self.save,
                  bg="#4CAF50", fg="white", padx=25).pack(side=tk.LEFT, padx=(0, 10))
        tk.Button(buttons_frame, text="Отмена", command=self.cancel,
                  padx=25).pack(side=tk.LEFT)

    def toggle_password(self):
        self.password_entry.config(show="" if self.show_password.get() else "*")

    def center_window(self, parent):
        self.window.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() // 2) - (self.window.winfo_width() // 2)
        y = parent.winfo_y() + (parent.winfo_height() // 2) - (self.window.winfo_height() // 2)
        self.window.geometry(f"+{x}+{y}")

    def save(self):
        site = self.site_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        notes = self.notes_text.get(1.0, tk.END).strip()

        if not site or not username or not password:
            messagebox.showerror("Ошибка", "Обязательные поля не заполнены", parent=self.window)
            return

        self.result = (site, username, password, notes)
        self.window.destroy()

    def cancel(self):
        self.result = None
        self.window.destroy()


class HelpWindow:
    """Окно справки"""

    def __init__(self, parent):
        self.window = tk.Toplevel(parent)
        self.window.title("Справка - LocalPassManager")

        frame = tk.Frame(self.window, padx=20, pady=20)
        frame.pack(fill=tk.BOTH, expand=True)

        text_widget = tk.Text(frame, wrap=tk.WORD, font=("Arial", 11),
                              bg="#f8f9fa", padx=15, pady=15)
        scrollbar = tk.Scrollbar(frame, orient=tk.VERTICAL, command=text_widget.yview)
        text_widget.configure(yscrollcommand=scrollbar.set)

        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        text_widget.insert(tk.END, HELP_TEXT)
        text_widget.config(state=tk.DISABLED)

        close_btn = tk.Button(self.window, text="Закрыть", command=self.window.destroy,
                              bg="#2196F3", fg="white", padx=35)
        close_btn.pack(pady=15)

        self.window.geometry("700x600")
        self.window.minsize(600, 500)


class PasswordManagerApp:
    """Главное окно приложения"""

    def __init__(self, password_manager):
        self.pm = password_manager
        self.window = tk.Tk()
        self.window.title(f"{APP_TITLE} v{APP_VERSION}")
        self.window.geometry("650x850")  # Увеличена ширина
        self.window.minsize(600, 800)

        # Применяем иконку
        if os.path.exists(ICON_FILE):
            try:
                self.window.iconbitmap(ICON_FILE)
            except:
                pass

        self.setup_ui()
        self.setup_bindings()
        self.refresh_entries()

    def setup_ui(self):
        main_frame = tk.Frame(self.window, padx=12, pady=12)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Секция генерации паролей
        gen_frame = tk.LabelFrame(main_frame, text="Генерация паролей", padx=8, pady=8)
        gen_frame.pack(fill=tk.X, pady=(0, 12))

        gen_controls = tk.Frame(gen_frame)
        gen_controls.pack(fill=tk.X)

        tk.Label(gen_controls, text="Длина:").pack(side=tk.LEFT)
        self.length_var = tk.StringVar(value="16")
        length_combo = ttk.Combobox(gen_controls, textvariable=self.length_var,
                                    values=["8", "12", "16", "20", "24", "32"], width=5)
        length_combo.pack(side=tk.LEFT, padx=(5, 12))

        self.uppercase_var = tk.BooleanVar(value=True)
        tk.Checkbutton(gen_controls, text="A-Z", variable=self.uppercase_var).pack(side=tk.LEFT, padx=(0, 5))

        self.lowercase_var = tk.BooleanVar(value=True)
        tk.Checkbutton(gen_controls, text="a-z", variable=self.lowercase_var).pack(side=tk.LEFT, padx=(0, 5))

        self.numbers_var = tk.BooleanVar(value=True)
        tk.Checkbutton(gen_controls, text="0-9", variable=self.numbers_var).pack(side=tk.LEFT, padx=(0, 5))

        self.symbols_var = tk.BooleanVar(value=True)
        tk.Checkbutton(gen_controls, text="!@#", variable=self.symbols_var).pack(side=tk.LEFT, padx=(0, 10))

        gen_btn = tk.Button(gen_controls, text="Генерировать (Ctrl+G)",
                            command=self.generate_password,
                            bg="#2196F3", fg="white")
        gen_btn.pack(side=tk.RIGHT)

        self.generated_pass_var = tk.StringVar()
        gen_entry = tk.Entry(gen_frame, textvariable=self.generated_pass_var,
                             font=("Courier", 11), state="readonly", bg="#f0f0f0")
        gen_entry.pack(fill=tk.X, pady=(8, 0))

        # Секция добавления пароля
        add_frame = tk.LabelFrame(main_frame, text="Добавить пароль", padx=8, pady=8)
        add_frame.pack(fill=tk.X, pady=(0, 12))

        tk.Label(add_frame, text="Сайт/Сервис:").pack(anchor=tk.W)
        self.site_var = tk.StringVar()
        tk.Entry(add_frame, textvariable=self.site_var).pack(fill=tk.X, pady=(2, 8))

        tk.Label(add_frame, text="Имя пользователя/Email:").pack(anchor=tk.W)
        self.username_var = tk.StringVar()
        tk.Entry(add_frame, textvariable=self.username_var).pack(fill=tk.X, pady=(2, 8))

        pass_frame = tk.Frame(add_frame)
        pass_frame.pack(fill=tk.X, pady=(0, 8))

        tk.Label(pass_frame, text="Пароль:").pack(anchor=tk.W)
        pass_input_frame = tk.Frame(pass_frame)
        pass_input_frame.pack(fill=tk.X, pady=(2, 0))

        self.password_var = tk.StringVar()
        self.password_entry = tk.Entry(pass_input_frame, textvariable=self.password_var, show="*")
        self.password_entry.pack(fill=tk.X, side=tk.LEFT)

        tk.Button(pass_input_frame, text="Использовать сгенерированный",
                  command=self.use_generated_password).pack(side=tk.RIGHT, padx=(8, 0))

        self.show_add_password = tk.BooleanVar()
        tk.Checkbutton(pass_frame, text="Показать пароль",
                       variable=self.show_add_password,
                       command=self.toggle_add_password).pack(anchor=tk.W, pady=(5, 0))

        tk.Label(add_frame, text="Примечания (необязательно):").pack(anchor=tk.W)

        notes_frame = tk.Frame(add_frame)
        notes_frame.pack(fill=tk.X, pady=(2, 8))

        self.notes_text = tk.Text(notes_frame, height=3, wrap=tk.WORD)
        notes_scrollbar = tk.Scrollbar(notes_frame, orient=tk.VERTICAL, command=self.notes_text.yview)
        self.notes_text.configure(yscrollcommand=notes_scrollbar.set)

        self.notes_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        notes_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        add_btn = tk.Button(add_frame, text="Добавить пароль (Ctrl+A)",
                            command=self.add_password,
                            bg="#4CAF50", fg="white", font=("Arial", 10, "bold"))
        add_btn.pack(pady=(8, 0))

        # Секция поиска и просмотра
        search_frame = tk.LabelFrame(main_frame, text="Поиск и просмотр паролей", padx=8, pady=8)
        search_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 12))

        search_bar = tk.Frame(search_frame)
        search_bar.pack(fill=tk.X, pady=(0, 8))

        tk.Label(search_bar, text="Поиск:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_entry = tk.Entry(search_bar, textvariable=self.search_var)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(8, 8))
        self.search_var.trace('w', self.on_search_change)

        tk.Button(search_bar, text="Очистить", command=self.clear_search).pack(side=tk.RIGHT)

        list_frame = tk.Frame(search_frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        self.results_listbox = tk.Listbox(list_frame, font=("Arial", 10))
        list_scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.results_listbox.yview)
        self.results_listbox.configure(yscrollcommand=list_scrollbar.set)

        self.results_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        list_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.results_listbox.bind('<Double-Button-1>', lambda e: self.view_password())

        entries_buttons = tk.Frame(search_frame)
        entries_buttons.pack(fill=tk.X, pady=(8, 0))

        tk.Button(entries_buttons, text="Просмотр", command=self.view_password,
                  bg="#FF9800", fg="white").pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(entries_buttons, text="Редактировать (F2)", command=self.edit_password,
                  bg="#2196F3", fg="white").pack(side=tk.LEFT, padx=(0, 8))

        tk.Button(entries_buttons, text="Удалить (Del)", command=self.delete_password,
                  bg="#f44336", fg="white").pack(side=tk.LEFT)

        # Нижняя панель
        bottom_frame = tk.Frame(main_frame)
        bottom_frame.pack(fill=tk.X, pady=(8, 0))

        tk.Button(bottom_frame, text="Экспорт (Ctrl+E)", command=self.export_data).pack(side=tk.LEFT)
        tk.Button(bottom_frame, text="Импорт", command=self.import_data).pack(side=tk.LEFT, padx=(8, 0))
        tk.Button(bottom_frame, text="Сменить пароль (Ctrl+M)",
                  command=self.change_master_password).pack(side=tk.LEFT, padx=(8, 0))

        tk.Button(bottom_frame, text="🔒 Заблокировать (Ctrl+L)", command=self.lock_manager,
                  bg="#ff5722", fg="white").pack(side=tk.LEFT, padx=(8, 0))

        tk.Button(bottom_frame, text="Справка (F1)", command=self.show_help).pack(side=tk.RIGHT)

    def setup_bindings(self):
        self.window.bind('<F1>', lambda e: self.show_help())
        self.window.bind('<F2>', lambda e: self.edit_password())
        self.window.bind('<Delete>', lambda e: self.delete_password())
        self.window.bind('<KeyPress>', self.handle_keypress)

    def handle_keypress(self, event):
        if event.state & 0x4:  # Ctrl
            if event.keycode == 71:  # G
                self.generate_password()
                return 'break'
            elif event.keycode == 65:  # A
                self.add_password()
                return 'break'
            elif event.keycode == 70:  # F
                self.search_entry.focus()
                return 'break'
            elif event.keycode == 69:  # E
                self.export_data()
                return 'break'
            elif event.keycode == 77:  # M
                self.change_master_password()
                return 'break'
            elif event.keycode == 76:  # L
                self.lock_manager()
                return 'break'

    def toggle_add_password(self):
        self.password_entry.config(show="" if self.show_add_password.get() else "*")

    def generate_password(self):
        try:
            length = int(self.length_var.get())
            password = generate_password(
                length=length,
                include_uppercase=self.uppercase_var.get(),
                include_lowercase=self.lowercase_var.get(),
                include_numbers=self.numbers_var.get(),
                include_symbols=self.symbols_var.get()
            )
            self.generated_pass_var.set(password)
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка генерации пароля: {e}")

    def use_generated_password(self):
        if self.generated_pass_var.get():
            self.password_var.set(self.generated_pass_var.get())
        else:
            messagebox.showwarning("Предупреждение", "Сначала сгенерируйте пароль")

    def add_password(self):
        site = self.site_var.get().strip()
        username = self.username_var.get().strip()
        password = self.password_var.get()
        notes = self.notes_text.get(1.0, tk.END).strip()

        if not site or not username or not password:
            messagebox.showerror("Ошибка", "Заполните обязательные поля")
            return

        if self.pm.add_password(site, username, password, notes):
            messagebox.showinfo("Успех", f"Пароль для {site} добавлен")
            self.site_var.set("")
            self.username_var.set("")
            self.password_var.set("")
            self.notes_text.delete(1.0, tk.END)
            self.show_add_password.set(False)
            self.password_entry.config(show="*")
            self.refresh_entries()
        else:
            messagebox.showerror("Ошибка", "Не удалось сохранить пароль")

    def edit_password(self):
        selection = self.results_listbox.curselection()
        if not selection:
            messagebox.showwarning("Предупреждение", "Выберите запись")
            return

        entry_text = self.results_listbox.get(selection[0])
        try:
            site, username = entry_text.split(" - ", 1)
            password, notes = self.pm.get_password(site, username)
            if not password:
                messagebox.showerror("Ошибка", "Пароль не найден")
                return

            dialog = EditPasswordDialog(self.window, site, username, password, notes)
            self.window.wait_window(dialog.window)

            if dialog.result:
                new_site, new_username, new_password, new_notes = dialog.result
                if self.pm.edit_password(site, username, new_site, new_username, new_password, new_notes):
                    messagebox.showinfo("Успех", "Пароль изменен")
                    self.refresh_entries()
                else:
                    messagebox.showerror("Ошибка", "Не удалось изменить пароль")
        except ValueError:
            messagebox.showerror("Ошибка", "Неверный формат записи")

    def delete_password(self):
        selection = self.results_listbox.curselection()
        if not selection:
            messagebox.showwarning("Предупреждение", "Выберите запись")
            return

        entry_text = self.results_listbox.get(selection[0])
        try:
            site, username = entry_text.split(" - ", 1)

            if messagebox.askyesno("Подтверждение", f"Удалить пароль для {site} ({username})?"):
                if self.pm.delete_password(site, username):
                    messagebox.showinfo("Успех", "Пароль удален")
                    self.refresh_entries()
                else:
                    messagebox.showerror("Ошибка", "Не удалось удалить пароль")
        except ValueError:
            messagebox.showerror("Ошибка", "Неверный формат записи")

    def view_password(self):
        selection = self.results_listbox.curselection()
        if not selection:
            messagebox.showwarning("Предупреждение", "Выберите запись")
            return

        entry_text = self.results_listbox.get(selection[0])
        try:
            site, username = entry_text.split(" - ", 1)
            password, notes = self.pm.get_password(site, username)
            if password:
                message = f"Сайт: {site}\nПользователь: {username}\nПароль: {password}"
                if notes:
                    message += f"\n\nПримечания:\n{notes}"
                messagebox.showinfo("Информация о пароле", message)
            else:
                messagebox.showerror("Ошибка", "Пароль не найден")
        except ValueError:
            messagebox.showerror("Ошибка", "Неверный формат записи")

    def on_search_change(self, *args):
        self.refresh_entries()

    def clear_search(self):
        self.search_var.set("")

    def refresh_entries(self):
        self.results_listbox.delete(0, tk.END)

        query = self.search_var.get().strip()
        if query:
            entries = self.pm.search_entries(query)
        else:
            entries = self.pm.get_all_entries()

        for site, username in entries:
            self.results_listbox.insert(tk.END, f"{site} - {username}")

    def export_data(self):
        # Показываем диалог настроек экспорта
        dialog = ExportImportDialog(self.window, mode="export")
        self.window.wait_window(dialog.window)

        if not dialog.result:
            return

        encrypted = dialog.result["encrypted"]

        filepath = filedialog.asksaveasfilename(
            title="Экспорт паролей",
            defaultextension=".json",
            filetypes=[("JSON файлы", "*.json")]
        )
        if filepath:
            if self.pm.export_data(filepath, encrypted=encrypted):
                mode_text = "зашифрованном" if encrypted else "расшифрованном"
                messagebox.showinfo("Успех", f"База данных экспортирована в {mode_text} виде")
            else:
                messagebox.showerror("Ошибка", "Ошибка экспорта")

    def import_data(self):
        # Показываем диалог настроек импорта
        dialog = ExportImportDialog(self.window, mode="import")
        self.window.wait_window(dialog.window)

        if not dialog.result:
            return

        import_mode = dialog.result["mode"]

        filepath = filedialog.askopenfilename(
            title="Импорт паролей",
            filetypes=[("JSON файлы", "*.json")]
        )
        if not filepath:
            return

        # Проверяем, зашифрованные ли данные
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                import_data = json.load(f)

            is_encrypted = import_data.get("encrypted", True)

            if is_encrypted:
                # Запрашиваем мастер-пароль импортируемой базы
                import_password = simpledialog.askstring(
                    "Импорт зашифрованных данных",
                    "Введите мастер-пароль импортируемой базы данных:",
                    show='*',
                    parent=self.window
                )

                if not import_password:
                    return

                if self.pm.import_data(filepath, mode=import_mode, import_master_password=import_password):
                    mode_text = "заменена" if import_mode == "replace" else "обновлена"
                    messagebox.showinfo("Успех", f"База данных успешно {mode_text}")
                    self.refresh_entries()
                else:
                    messagebox.showerror("Ошибка", "Неверный мастер-пароль или ошибка импорта")
            else:
                # Расшифрованные данные - импортируем без пароля
                if self.pm.import_data(filepath, mode=import_mode):
                    mode_text = "заменена" if import_mode == "replace" else "обновлена"
                    messagebox.showinfo("Успех", f"База данных успешно {mode_text}")
                    self.refresh_entries()
                else:
                    messagebox.showerror("Ошибка", "Ошибка импорта")

        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка чтения файла: {e}")

    def lock_manager(self):
        """Блокирует менеджер и требует повторного ввода мастер-пароля"""
        self.pm.save_data()
        self.window.withdraw()

        max_attempts = 3
        for attempt in range(max_attempts):
            # Используем mode="enter" для ввода существующего пароля
            dialog = MasterPasswordDialog(self.window, mode="enter",
                                          attempts_left=max_attempts - attempt)
            self.window.wait_window(dialog.dialog)

            if dialog.result:
                if dialog.result == self.pm.master_password:
                    self.window.deiconify()
                    self.window.lift()
                    self.window.focus_force()
                    return
                else:
                    if attempt < max_attempts - 1:
                        messagebox.showerror("Ошибка",
                                             f"Неверный мастер-пароль.\nОсталось попыток: {max_attempts - attempt - 1}",
                                             parent=self.window)
                    else:
                        messagebox.showerror("Ошибка",
                                             "Исчерпаны все попытки ввода пароля.\nПрограмма будет закрыта.",
                                             parent=self.window)
                        self.window.destroy()
                        return
            else:
                self.window.destroy()
                return

    def change_master_password(self):
        dialog = ChangeMasterPasswordDialog(self.window, self.pm)
        self.window.wait_window(dialog.window)

    def show_help(self):
        HelpWindow(self.window)

    def run(self):
        self.window.mainloop()


def main():
    """Главная функция программы"""
    try:
        password_manager = PasswordManager()

        if os.path.exists(CONFIG_FILE):
            max_attempts = 3
            for attempt in range(max_attempts):
                dialog = MasterPasswordDialog(None, mode="enter",
                                              attempts_left=max_attempts - attempt)
                dialog.dialog.mainloop()

                if dialog.result:
                    if password_manager.unlock_database(dialog.result):
                        break
                    else:
                        if attempt < max_attempts - 1:
                            temp_root = tk.Tk()
                            temp_root.withdraw()
                            messagebox.showerror("Ошибка",
                                                 f"Неверный мастер-пароль.\nОсталось попыток: {max_attempts - attempt - 1}",
                                                 parent=temp_root)
                            temp_root.destroy()
                        else:
                            temp_root = tk.Tk()
                            temp_root.withdraw()
                            messagebox.showerror("Ошибка",
                                                 "Исчерпаны все попытки ввода пароля.\nПрограмма будет закрыта.",
                                                 parent=temp_root)
                            temp_root.destroy()
                            return
                else:
                    return
        else:
            dialog = MasterPasswordDialog(None, mode="create")
            dialog.dialog.mainloop()

            if dialog.result:
                if not password_manager.setup_new_database(dialog.result):
                    temp_root = tk.Tk()
                    temp_root.withdraw()
                    messagebox.showerror("Ошибка", "Не удалось создать базу данных", parent=temp_root)
                    temp_root.destroy()
                    return
            else:
                return

        app = PasswordManagerApp(password_manager)
        app.run()

    except Exception as e:
        try:
            temp_root = tk.Tk()
            temp_root.withdraw()
            messagebox.showerror("Критическая ошибка", f"Произошла ошибка: {e}", parent=temp_root)
            temp_root.destroy()
        except:
            print(f"Критическая ошибка: {e}")


if __name__ == "__main__":
    main()