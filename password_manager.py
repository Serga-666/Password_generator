
import json
import os
import shutil
import base64
import hmac
import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import argon2
import secrets
import sys
import io
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

# Наборы символов для генерации паролей
digits = '0123456789'
lowercase_letters = 'abcdefghijklmnopqrstuvwxyz'
uppercase_letters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
punctuation = '!#$%&*+-=?@^_'
bad_symbols = 'il1Lo0O'

# Конфигурация криптографии
SALT_SIZE = 16
IV_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 100000

# Инициализация Argon2
argon2_hasher = argon2.PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16
)


def handle_errors(func):
    """Декоратор для обработки ошибок криптографии"""

    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except ValueError as e:
            print(f"❌ Ошибка: {e}")
            return None
        except Exception as e:
            print(f"❌ Неожиданная ошибка: {e}")
            return None

    return wrapper


def secure_erase(data):
    """Безопасное удаление данных из памяти"""
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, bytes):
        secure_erase(bytearray(data))
    elif isinstance(data, str):
        secure_erase(data.encode())


def derive_key_from_password(password: str, salt: bytes) -> bytes:
    """Производный ключ из пароля с использованием PBKDF2"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


@handle_errors
def encrypt_data(data: str, key: bytes) -> dict:
    """Шифрование данных с использованием AES-GCM"""
    iv = secrets.token_bytes(IV_SIZE)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    encrypted_data = encryptor.update(data.encode()) + encryptor.finalize()

    return {
        'iv': base64.b64encode(iv).decode(),
        'data': base64.b64encode(encrypted_data).decode(),
        'tag': base64.b64encode(encryptor.tag).decode()
    }


@handle_errors
def decrypt_data(encrypted_dict: dict, key: bytes) -> str:
    """Дешифрование данных с использованием AES-GCM"""
    try:
        iv = base64.b64decode(encrypted_dict['iv'])
        encrypted_data = base64.b64decode(encrypted_dict['data'])
        tag = base64.b64decode(encrypted_dict['tag'])

        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()

        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()
        return decrypted_data.decode()
    except Exception as e:
        raise ValueError("Ошибка дешифрования: неверный ключ или поврежденные данные")


def calculate_hmac(data: bytes, key: bytes) -> str:
    """Вычисление HMAC для проверки целостности данных"""
    h = hmac.new(key, data, hashlib.sha256)
    return base64.b64encode(h.digest()).decode()


def verify_hmac(data: bytes, key: bytes, received_hmac: str) -> bool:
    """Проверка HMAC для верификации целостности данных"""
    try:
        expected_hmac = calculate_hmac(data, key)
        return hmac.compare_digest(expected_hmac, received_hmac)
    except Exception:
        return False


def setup_master_password():
    """Настройка мастер-пароля"""
    if os.path.exists("master_config.json"):
        print("✅ Мастер-пароль уже настроен.")
        return True

    print("=== НАСТРОЙКА МАСТЕР-ПАРОЛЯ ===")
    print("Создайте надежный мастер-пароль для защиты всех ваших паролей")
    print("Минимальная длина: 12 символов, рекомендуемая: 16+ символов")

    while True:
        try:
            print("\n" + "=" * 40)
            password = input("Введите новый мастер-пароль: ")

            if len(password) < 12:
                print("❌ Пароль слишком короткий. Минимум 12 символов.")
                continue

            confirm = input("Подтвердите мастер-пароль: ")

            if password != confirm:
                print("❌ Пароли не совпадают. Попробуйте снова.")
                continue

            # Генерируем соль и хеш
            master_salt = secrets.token_bytes(SALT_SIZE)
            password_hash = argon2_hasher.hash(password)

            config = {
                'password_hash': password_hash,
                'master_salt': base64.b64encode(master_salt).decode(),
                'iterations': ITERATIONS,
                'created': datetime.now().isoformat()
            }

            with open("master_config.json", "w", encoding="utf-8") as f:
                json.dump(config, f, indent=4, ensure_ascii=False)

            print("✅ Мастер-пароль успешно установлен!")
            return True

        except KeyboardInterrupt:
            print("\n❌ Настройка отменена пользователем")
            return False
        except Exception as e:
            print(f"❌ Ошибка при настройке: {e}")
            return False


def verify_master_password() -> bytes:
    """Проверка мастер-пароля и получение ключа"""
    if not os.path.exists("master_config.json"):
        print("❌ Мастер-пароль не настроен.")
        return None

    try:
        with open("master_config.json", "r", encoding="utf-8") as f:
            config = json.load(f)

        # Используем сохранённую соль!
        master_salt = base64.b64decode(config['master_salt'])

        attempts = 3
        while attempts > 0:
            print(f"\nПопытка {4 - attempts} из 3")
            password = input("Введите мастер-пароль: ")

            try:
                # Проверяем хеш
                argon2_hasher.verify(config['password_hash'], password)

                # Генерируем ключ ИЗ СОХРАНЕННОЙ СОЛИ
                key = derive_key_from_password(password, master_salt)

                print("✅ Пароль верный!")
                return key

            except argon2.exceptions.VerifyMismatchError:
                attempts -= 1
                if attempts > 0:
                    print(f"❌ Неверный пароль. Осталось попыток: {attempts}")
                else:
                    print("❌ Слишком много неудачных попыток. Программа завершена.")
                    return None
            except Exception as e:
                print(f"❌ Ошибка проверки пароля: {e}")
                return None

    except Exception as e:
        print(f"❌ Ошибка загрузки конфигурации: {e}")
        return None


def ask_choice(prompt):
    """Функция проверки выбора"""
    while True:
        choice = input(prompt).strip().lower()
        if choice in ['д', 'y', 'yes', 'да']:
            return True
        elif choice in ['н', 'n', 'no', 'нет']:
            return False
        else:
            print("Введите 'д' или 'н'.")


def get_user_choices(single_password=False):
    """Запрос параметров для генерации пароля"""
    chars = ''
    while True:
        try:
            n = 1 if single_password else int(input('Введите количество паролей для генерации: '))
            length = int(input('Введите длину пароля: '))
            if n <= 0 or length <= 0:
                raise ValueError("Количество и длина паролей должны быть положительными.")
            break
        except ValueError as e:
            print(f"Ошибка ввода: {e}")

    if ask_choice('Включить цифры? (д/н): '):
        chars += digits
    if ask_choice('Включить строчные буквы? (д/н): '):
        chars += lowercase_letters
    if ask_choice('Включить заглавные буквы? (д/н): '):
        chars += uppercase_letters
    if ask_choice('Включить спецсимволы (!#$%& и т.п.)? (д/н): '):
        chars += punctuation
    if not ask_choice('Оставить символы "il1Lo0O"? (д/н): '):
        for ch in bad_symbols:
            chars = chars.replace(ch, '')

    return chars, n, length


def generate_password(length, chars):
    """Генерация пароля"""
    if not chars:
        raise ValueError("Не выбрано ни одного типа символов!")
    return ''.join(secrets.choice(chars) for _ in range(length))


def save_password_data(encrypted_data: dict, key: bytes):
    """Сохранение зашифрованных данных с HMAC"""
    data_str = json.dumps(encrypted_data, ensure_ascii=False)
    hmac_value = calculate_hmac(data_str.encode(), key)

    data_to_save = {
        'data': encrypted_data,
        'hmac': hmac_value,
        'timestamp': datetime.now().isoformat()
    }

    with open("passwords.json", "w", encoding="utf-8") as f:
        json.dump(data_to_save, f, indent=4, ensure_ascii=False)


def load_password_data(key: bytes) -> dict:
    """Загрузка зашифрованных данных с проверкой HMAC"""
    if not os.path.exists("passwords.json"):
        return {}

    try:
        with open("passwords.json", "r", encoding="utf-8") as f:
            saved_data = json.load(f)

        # Проверяем целостность данных
        data_str = json.dumps(saved_data['data'], ensure_ascii=False)
        if not verify_hmac(data_str.encode(), key, saved_data['hmac']):
            print("⚠️  Внимание: Данные могли быть изменены! Целостность не гарантируется.")
            if not ask_choice("Продолжить загрузку? (д/н): "):
                return {}

        return saved_data['data']
    except Exception as e:
        print(f"❌ Ошибка загрузки данных: {e}")
        return {}


@handle_errors
def add_password(key: bytes):
    """Добавление нового пароля"""
    service = input("Введите название сервиса: ").strip()

    print("\nВыберите способ создания пароля:")
    print("1. Сгенерировать автоматически")
    print("2. Ввести вручную")

    choice = input("Ваш выбор: ").strip()

    if choice == "1":
        chars, _, length = get_user_choices(single_password=True)
        password = generate_password(length, chars)
        print(f"Сгенерированный пароль: {password}")
    elif choice == "2":
        password = input("Введите пароль: ").strip()
    else:
        print("Неверный выбор.")
        return

    # Шифруем сервис и пароль ОТДЕЛЬНО с разными IV
    encrypted_service = encrypt_data(service, key)
    encrypted_password = encrypt_data(password, key)

    if not encrypted_service or not encrypted_password:
        print("❌ Ошибка шифрования данных")
        return

    # Загружаем существующие данные
    data = load_password_data(key)

    # Сохраняем в правильной структуре
    data[encrypted_service['data']] = {
        'service_iv': encrypted_service['iv'],
        'service_tag': encrypted_service['tag'],
        'password_iv': encrypted_password['iv'],
        'password_data': encrypted_password['data'],
        'password_tag': encrypted_password['tag']
    }

    save_password_data(data, key)
    print(f"✅ Пароль для '{service}' успешно сохранён!")


@handle_errors
def view_passwords(key: bytes):
    """Просмотр паролей"""
    data = load_password_data(key)

    if not data:
        print("📭 Нет сохранённых паролей.")
        return

    print("\n📋 Список сохранённых сервисов:")
    services = []
    service_mapping = {}

    for encrypted_service_data, encrypted_data in data.items():
        try:
            # Правильное дешифрование сервиса с его собственным TAG
            service = decrypt_data({
                'iv': encrypted_data['service_iv'],
                'data': encrypted_service_data,
                'tag': encrypted_data['service_tag']
            }, key)
            services.append(service)
            service_mapping[service] = (encrypted_service_data, encrypted_data)
        except Exception as e:
            print(f"❌ Ошибка дешифрования сервиса: {e}")
            continue

    if not services:
        print("❌ Не удалось расшифровать сервисы.")
        return

    for i, service in enumerate(services, 1):
        print(f"{i}. {service}")

    while True:
        try:
            choice = int(input("Введите номер сервиса для просмотра пароля: "))
            if 1 <= choice <= len(services):
                service = services[choice - 1]
                encrypted_service_data, encrypted_data = service_mapping[service]

                # Дешифруем пароль
                password = decrypt_data({
                    'iv': encrypted_data['password_iv'],
                    'data': encrypted_data['password_data'],
                    'tag': encrypted_data['password_tag']
                }, key)

                print(f"\n🔓 Сервис: {service}")
                print(f"🔓 Пароль: {password}")
                break
            else:
                raise ValueError()
        except ValueError:
            print("❌ Некорректный выбор. Попробуйте снова.")


@handle_errors
def delete_password(key: bytes):
    """Удаление пароля"""
    data = load_password_data(key)

    if not data:
        print("📭 Нет сохранённых паролей.")
        return

    # Получаем список сервисов для отображения
    services = []
    service_mapping = {}

    for encrypted_service_data, encrypted_data in data.items():
        try:
            # Правильное дешифрование сервиса
            service = decrypt_data({
                'iv': encrypted_data['service_iv'],
                'data': encrypted_service_data,
                'tag': encrypted_data['service_tag']
            }, key)
            services.append(service)
            service_mapping[service] = encrypted_service_data
        except Exception as e:
            print(f"❌ Ошибка дешифрования сервиса: {e}")
            continue

    if not services:
        print("❌ Не удалось расшифровать сервисы.")
        return

    print("\n📋 Список сохранённых сервисов:")
    for i, service in enumerate(services, 1):
        print(f"{i}. {service}")

    while True:
        try:
            choice = int(input("Введите номер сервиса для удаления: "))
            if 1 <= choice <= len(services):
                service_to_delete = services[choice - 1]
                encrypted_service_data = service_mapping[service_to_delete]

                confirm = input(
                    f"Вы уверены, что хотите удалить пароль для '{service_to_delete}'? (д/н): ").strip().lower()
                if confirm == 'д':
                    del data[encrypted_service_data]
                    save_password_data(data, key)
                    print(f"✅ Пароль для '{service_to_delete}' успешно удалён.")
                else:
                    print("❌ Удаление отменено.")
                break
            else:
                raise ValueError()
        except ValueError:
            print("❌ Некорректный ввод. Попробуйте снова.")


@handle_errors
def change_password(key: bytes):
    """Изменение существующего пароля"""
    data = load_password_data(key)

    if not data:
        print("📭 Нет сохранённых паролей.")
        return

    # Получаем список сервисов
    services = []
    service_mapping = {}

    for encrypted_service_data, encrypted_data in data.items():
        try:
            # Правильное дешифрование сервиса
            service = decrypt_data({
                'iv': encrypted_data['service_iv'],
                'data': encrypted_service_data,
                'tag': encrypted_data['service_tag']
            }, key)
            services.append(service)
            service_mapping[service] = encrypted_service_data
        except Exception as e:
            print(f"❌ Ошибка дешифрования сервиса: {e}")
            continue

    if not services:
        print("❌ Не удалось расшифровать сервисы.")
        return

    print("\n📋 Список сохранённых сервисов:")
    for i, service in enumerate(services, 1):
        print(f"{i}. {service}")

    while True:
        try:
            choice = int(input("Введите номер сервиса для изменения пароля: "))
            if 1 <= choice <= len(services):
                service_to_change = services[choice - 1]
                encrypted_service_data = service_mapping[service_to_change]

                print("Выберите способ изменения пароля:")
                print("1. Сгенерировать автоматически")
                print("2. Ввести вручную")

                method = input("Ваш выбор: ").strip()

                if method == "1":
                    chars, _, length = get_user_choices(single_password=True)
                    new_password = generate_password(length, chars)
                    print(f"Сгенерированный пароль: {new_password}")
                elif method == "2":
                    new_password = input("Введите новый пароль: ").strip()
                else:
                    print("❌ Неверный выбор.")
                    return

                # Шифруем новый пароль
                encrypted_password = encrypt_data(new_password, key)

                if not encrypted_password:
                    print("❌ Ошибка шифрования пароля")
                    return

                # Обновляем данные пароля (сервис остается тот же)
                data[encrypted_service_data]['password_iv'] = encrypted_password['iv']
                data[encrypted_service_data]['password_data'] = encrypted_password['data']
                data[encrypted_service_data]['password_tag'] = encrypted_password['tag']

                save_password_data(data, key)
                print(f"✅ Пароль для '{service_to_change}' успешно изменён!")
                break

            else:
                raise ValueError()
        except ValueError:
            print("❌ Некорректный ввод. Попробуйте снова.")


def backup_data(key: bytes):
    """Создание резервной копии"""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_dir = "backups"

    if not os.path.exists(backup_dir):
        os.makedirs(backup_dir)

    files_to_backup = ["passwords.json", "master_config.json"]
    backed_up = 0

    for file in files_to_backup:
        if os.path.exists(file):
            shutil.copy2(file, os.path.join(backup_dir, f"{timestamp}_{file}"))
            backed_up += 1

    if backed_up > 0:
        print(f"✅ Резервная копия создана: {timestamp}")
    else:
        print("❌ Нет данных для резервного копирования.")


def restore_backup(key: bytes):
    """Восстановление из резервной копии"""
    backup_dir = "backups"
    if not os.path.exists(backup_dir) or not os.listdir(backup_dir):
        print("📭 Резервные копии отсутствуют.")
        return

    backups = [f for f in os.listdir(backup_dir) if f.endswith('.json')]
    if not backups:
        print("📭 Резервные копии отсутствуют.")
        return

    print("\n📋 Доступные резервные копии:")
    backups.sort(reverse=True)
    for i, backup in enumerate(backups[:10], 1):
        print(f"{i}. {backup}")

    try:
        choice = int(input("Выберите номер резервной копии: "))
        if 1 <= choice <= len(backups):
            backup_file = backups[choice - 1]
            timestamp = backup_file.split('_')[0]

            # Восстанавливаем файлы
            for file in ["passwords.json", "master_config.json"]:
                backup_path = os.path.join(backup_dir, f"{timestamp}_{file}")
                if os.path.exists(backup_path):
                    shutil.copy2(backup_path, file)

            print("✅ Данные успешно восстановлены!")
        else:
            print("❌ Неверный выбор.")
    except (ValueError, IndexError):
        print("❌ Некорректный ввод.")


@handle_errors
def export_data(key: bytes):
    """Экспорт данных в незашифрованном виде"""
    data = load_password_data(key)

    if not data:
        print("📭 Нет данных для экспорта.")
        return

    decrypted_data = {}

    for encrypted_service_data, encrypted_data in data.items():
        try:
            # Правильное дешифрование сервиса
            service = decrypt_data({
                'iv': encrypted_data['service_iv'],
                'data': encrypted_service_data,
                'tag': encrypted_data['service_tag']
            }, key)

            # Дешифруем пароль
            password = decrypt_data({
                'iv': encrypted_data['password_iv'],
                'data': encrypted_data['password_data'],
                'tag': encrypted_data['password_tag']
            }, key)

            decrypted_data[service] = password

        except Exception as e:
            print(f"❌ Ошибка дешифрования: {e}")
            continue

    if not decrypted_data:
        print("❌ Не удалось расшифровать данные для экспорта.")
        return

    export_filename = input("Введите имя файла для экспорта: ").strip() or "passwords_export.json"

    with open(export_filename, "w", encoding="utf-8") as f:
        json.dump(decrypted_data, f, indent=4, ensure_ascii=False)

    print(f"✅ Данные экспортированы в файл: {export_filename}")


@handle_errors
def import_data(key: bytes):
    """Импорт данных"""
    import_filename = input("Введите имя файла для импорта: ").strip() or "passwords_import.json"

    if not os.path.exists(import_filename):
        print(f"❌ Файл {import_filename} не найден.")
        return

    try:
        with open(import_filename, "r", encoding="utf-8") as f:
            imported_data = json.load(f)
    except json.JSONDecodeError:
        print("❌ Ошибка: неверный формат JSON.")
        return

    existing_data = load_password_data(key)
    imported_count = 0

    for service, password in imported_data.items():
        try:
            # Шифруем сервис и пароль с разными IV
            encrypted_service = encrypt_data(service, key)
            encrypted_password = encrypt_data(password, key)

            if not encrypted_service or not encrypted_password:
                continue

            # Проверяем, нет ли уже такого сервиса
            if encrypted_service['data'] not in existing_data:
                existing_data[encrypted_service['data']] = {
                    'service_iv': encrypted_service['iv'],
                    'service_tag': encrypted_service['tag'],
                    'password_iv': encrypted_password['iv'],
                    'password_data': encrypted_password['data'],
                    'password_tag': encrypted_password['tag']
                }
                imported_count += 1

        except Exception as e:
            print(f"❌ Ошибка импорта записи '{service}': {e}")
            continue

    save_password_data(existing_data, key)
    print(f"✅ Импортировано {imported_count} записей.")


@handle_errors
def change_master_password(old_key: bytes) -> bytes:
    """Смена мастер-пароля"""
    print("\n=== СМЕНА МАСТЕР-ПАРОЛЯ ===")

    # Загружаем текущие данные
    data = load_password_data(old_key)
    if not data:
        print("📭 Нет данных для перешифрования.")
        return old_key

    # Запрашиваем новый пароль
    while True:
        new_password = input("Введите новый мастер-пароль: ")
        confirm = input("Подтвердите новый мастер-пароль: ")

        if new_password != confirm:
            print("❌ Пароли не совпадают. Попробуйте снова.")
            continue

        if len(new_password) < 12:
            print("❌ Пароль слишком короткий. Минимум 12 символов.")
            continue

        break

    # Генерируем новую соль и ключ
    new_salt = secrets.token_bytes(SALT_SIZE)
    new_key = derive_key_from_password(new_password, new_salt)
    new_password_hash = argon2_hasher.hash(new_password)

    # Перешифровываем все данные новым ключом
    new_data = {}
    total_items = len(data)
    processed = 0

    print("🔄 Перешифрование данных...")
    for encrypted_service_data, encrypted_data in data.items():
        try:
            # Дешифруем старым ключом
            service = decrypt_data({
                'iv': encrypted_data['service_iv'],
                'data': encrypted_service_data,
                'tag': encrypted_data['service_tag']
            }, old_key)

            password = decrypt_data({
                'iv': encrypted_data['password_iv'],
                'data': encrypted_data['password_data'],
                'tag': encrypted_data['password_tag']
            }, old_key)

            # Шифруем новым ключом
            new_encrypted_service = encrypt_data(service, new_key)
            new_encrypted_password = encrypt_data(password, new_key)

            if new_encrypted_service and new_encrypted_password:
                new_data[new_encrypted_service['data']] = {
                    'service_iv': new_encrypted_service['iv'],
                    'service_tag': new_encrypted_service['tag'],
                    'password_iv': new_encrypted_password['iv'],
                    'password_data': new_encrypted_password['data'],
                    'password_tag': new_encrypted_password['tag']
                }

            processed += 1
            print(f"🔒 Обработано: {processed}/{total_items}")

        except Exception as e:
            print(f"❌ Ошибка перешифрования: {e}")
            continue

    # Сохраняем новые данные
    save_password_data(new_data, new_key)

    # Обновляем конфигурацию мастер-пароля
    config = {
        'password_hash': new_password_hash,
        'master_salt': base64.b64encode(new_salt).decode(),
        'iterations': ITERATIONS,
        'updated': datetime.now().isoformat()
    }

    with open("master_config.json", "w", encoding="utf-8") as f:
        json.dump(config, f, indent=4, ensure_ascii=False)

    print("✅ Мастер-пароль успешно изменён! Все данные перешифрованы.")

    # Безопасно очищаем старый ключ из памяти
    secure_erase(old_key)

    return new_key


def main():
    """Главная функция"""
    print("🔐 ЗАГРУЗКА МЕНЕДЖЕРА ПАРОЛЕЙ...")

    if not setup_master_password():
        return

    key = verify_master_password()
    if not key:
        return

    try:
        while True:
            print("\n" + "=" * 50)
            print("🔐 МЕНЕДЖЕР ПАРОЛЕЙ (УСИЛЕННОЕ ШИФРОВАНИЕ)")
            print("=" * 50)
            print("1. Добавить новый пароль")
            print("2. Посмотреть пароли")
            print("3. Удалить пароль")
            print("4. Изменить пароль")
            print("5. Резервное копирование")
            print("6. Восстановление из резервной копии")
            print("7. Экспорт данных")
            print("8. Импорт данных")
            print("9. Сменить мастер-пароль")
            print("0. Выйти")
            print("=" * 50)

            choice = input("Ваш выбор: ").strip()

            if choice == "1":
                add_password(key)
            elif choice == "2":
                view_passwords(key)
            elif choice == "3":
                delete_password(key)
            elif choice == "4":
                change_password(key)
            elif choice == "5":
                backup_data(key)
            elif choice == "6":
                restore_backup(key)
            elif choice == "7":
                export_data(key)
            elif choice == "8":
                import_data(key)
            elif choice == "9":
                new_key = change_master_password(key)
                if new_key:
                    key = new_key
                else:
                    print("❌ Не удалось сменить мастер-пароль")
            elif choice == "0":
                print("👋 Выход из программы. Данные защищены!")
                break
            else:
                print("❌ Некорректный выбор. Попробуйте снова.")
    finally:
        # Безопасно очищаем ключ из памяти при выходе
        secure_erase(key)


if __name__ == "__main__":
    main()
