import os, base64, hashlib, wave
import tkinter as tk
from tkinter import filedialog, messagebox

import customtkinter as ctk

import cv2
import numpy as np
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes


# =========================
# 1) CRIPTO AES (igual que tu lógica)
# =========================
BS = 16

def _pad(data: bytes) -> bytes:
    pad_len = BS - len(data) % BS
    return data + bytes([pad_len]) * pad_len

def _unpad(data: bytes) -> bytes:
    pad_len = data[-1]
    if pad_len < 1 or pad_len > BS:
        raise ValueError("Padding incorrecto")
    return data[:-pad_len]

def _key_from_pass(password: str) -> bytes:
    return hashlib.sha256(password.encode()).digest()

def aes_encrypt(plaintext: str, password: str) -> str:
    if not password:
        raise ValueError("La contraseña no puede estar vacía.")
    key = _key_from_pass(password)
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ct = cipher.encrypt(_pad(plaintext.encode()))
    return base64.b64encode(iv + ct).decode()

def aes_decrypt(cipher_b64: str, password: str) -> str:
    if not password:
        raise ValueError("La contraseña no puede estar vacía.")
    raw = base64.b64decode(cipher_b64)
    iv, ct = raw[:16], raw[16:]
    cipher = AES.new(_key_from_pass(password), AES.MODE_CBC, iv)
    return _unpad(cipher.decrypt(ct)).decode()


# =========================
# 2) MORSE (igual que tu lógica)
# =========================
MORSE = {
    'A':'.-','B':'-...','C':'-.-.','D':'-..','E':'.','F':'..-.',
    'G':'--.','H':'....','I':'..','J':'.---','K':'-.-','L':'.-..',
    'M':'--','N':'-.','O':'---','P':'.--.','Q':'--.-','R':'.-.',
    'S':'...','T':'-','U':'..-','V':'...-','W':'.--','X':'-..-',
    'Y':'-.--','Z':'--..','1':'.----','2':'..---','3':'...--',
    '4':'....-','5':'.....','6':'-....','7':'--...','8':'---..',
    '9':'----.','0':'-----',' ':'/'
}
INV_MORSE = {v: k for k, v in MORSE.items()}

def to_morse(text: str) -> str:
    return ' '.join(MORSE.get(c.upper(), '') for c in text)

def from_morse(code: str) -> str:
    return ''.join(INV_MORSE.get(chunk, '') for chunk in code.split())


# =========================
# 3) ESTEGANOGRAFÍA WAV (igual que tu lógica)
# =========================
def wav_hide(cover_path, msg: str, out_path):
    with wave.open(cover_path, 'rb') as w:
        params = w.getparams()
        frames = bytearray(w.readframes(w.getnframes()))

    msg_bits = ''.join(f'{b:08b}' for b in msg.encode()) + '00000000'
    if len(msg_bits) > len(frames):
        raise ValueError("Archivo WAV demasiado pequeño para el mensaje.")

    for i, bit in enumerate(msg_bits):
        frames[i] = (frames[i] & 0b11111110) | int(bit)

    with wave.open(out_path, 'wb') as w:
        w.setparams(params)
        w.writeframes(frames)

def wav_extract(stego_path) -> str:
    with wave.open(stego_path, 'rb') as w:
        frames = w.readframes(w.getnframes())

    bits, byte = [], ''
    for b in frames:
        byte += str(b & 1)
        if len(byte) == 8:
            if byte == '00000000':
                break
            bits.append(int(byte, 2))
            byte = ''
    return bytes(bits).decode(errors='ignore')


# =========================
# 4) ESTEGANOGRAFÍA VIDEO (igual que tu lógica)
# =========================
def video_hide(cover_path, msg: str, out_path):
    cap = cv2.VideoCapture(cover_path)
    if not cap.isOpened():
        raise ValueError("No se pudo abrir el video de entrada.")

    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
    fps = cap.get(cv2.CAP_PROP_FPS) or 30
    w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
    h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
    out = cv2.VideoWriter(out_path, fourcc, fps, (w, h))

    msg_bits = ''.join(f'{b:08b}' for b in msg.encode()) + '00000000'
    bit_idx = 0

    while True:
        ret, frame = cap.read()
        if not ret:
            break

        if bit_idx < len(msg_bits):
            flat = frame.reshape(-1, 3)
            for pix in flat:
                if bit_idx >= len(msg_bits):
                    break
                pix[0] = (pix[0] & 0b11111110) | int(msg_bits[bit_idx])  # canal B
                bit_idx += 1
            frame = flat.reshape(frame.shape)

        out.write(frame)

    cap.release()
    out.release()

def video_extract(stego_path) -> str:
    cap = cv2.VideoCapture(stego_path)
    if not cap.isOpened():
        raise ValueError("No se pudo abrir el video.")

    bits, byte = [], ''
    while True:
        ret, frame = cap.read()
        if not ret:
            break

        for pix in frame.reshape(-1, 3):
            byte += str(pix[0] & 1)
            if len(byte) == 8:
                if byte == '00000000':
                    cap.release()
                    return bytes(bits).decode(errors='ignore')
                bits.append(int(byte, 2))
                byte = ''

    cap.release()
    return ''


# =========================
# 5) UI MODERNA (CustomTkinter)
# =========================
ctk.set_appearance_mode("light")
ctk.set_default_color_theme("blue")

class AppCTK(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("CryptoSteg CHRISTIAM ROMERO")
        self.geometry("1180x720")
        self.minsize(1020, 640)

        # ---------- Estado ----------
        self.status_var = tk.StringVar(value="Listo. Selecciona una pestaña para comenzar.")

        # Paths
        self.audio_cover = tk.StringVar()
        self.audio_out = tk.StringVar()
        self.audio_stego = tk.StringVar()

        self.vid_cover = tk.StringVar()
        self.vid_out = tk.StringVar()
        self.vid_stego = tk.StringVar()

        # ---------- Layout root ----------
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, width=260, corner_radius=0, fg_color="#f8fafc")
        self.sidebar.grid(row=0, column=0, sticky="nsw")
        self.sidebar.grid_rowconfigure(10, weight=1)

        ctk.CTkLabel(
            self.sidebar,
            text="CryptoSteg 2026",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#0f172a"
        ).grid(row=0, column=0, padx=18, pady=(20, 4), sticky="w")

        ctk.CTkLabel(
            self.sidebar,
            text="AES · WAV · Video · Morse",
            font=ctk.CTkFont(size=12),
            text_color="#64748b"
        ).grid(row=1, column=0, padx=18, pady=(0, 16), sticky="w")

        self.btn_clear_all = ctk.CTkButton(
            self.sidebar,
            text="🧹 Limpiar todo",
            height=40,
            command=self.clear_all
        )
        self.btn_clear_all.grid(row=2, column=0, padx=18, pady=(0, 10), sticky="ew")

        self.btn_about = ctk.CTkButton(
            self.sidebar,
            text="ℹ️ Ayuda",
            height=40,
            fg_color="#0ea5e9",
            hover_color="#0284c7",
            command=self.show_help
        )
        self.btn_about.grid(row=3, column=0, padx=18, pady=(0, 10), sticky="ew")

        # ---------- Main ----------
        self.main = ctk.CTkFrame(self, corner_radius=0, fg_color="#ffffff")
        self.main.grid(row=0, column=1, sticky="nsew")
        self.main.grid_columnconfigure(0, weight=1)
        self.main.grid_rowconfigure(1, weight=1)

        header = ctk.CTkFrame(self.main, fg_color="#ffffff")
        header.grid(row=0, column=0, sticky="ew", padx=22, pady=(18, 10))
        header.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(
            header,
            text="CryptoSteg Toolkit",
            font=ctk.CTkFont(size=22, weight="bold"),
            text_color="#0f172a"
        ).grid(row=0, column=0, sticky="w")

        ctk.CTkLabel(
            header,
            text="Software para realizar estegonografia",
            font=ctk.CTkFont(size=12),
            text_color="#64748b"
        ).grid(row=1, column=0, sticky="w", pady=(2, 0))

        # Tabs
        self.tabs = ctk.CTkTabview(self.main, corner_radius=14)
        self.tabs.grid(row=1, column=0, sticky="nsew", padx=22, pady=(0, 12))

        self.tab_crypto = self.tabs.add("🔐 Cifrar / Descifrar")
        self.tab_audio  = self.tabs.add("🎧 Audio Steg (WAV)")
        self.tab_video  = self.tabs.add("🎬 Video Steg")
        self.tab_morse  = self.tabs.add("📡 Morse")

        self.build_crypto_tab()
        self.build_audio_tab()
        self.build_video_tab()
        self.build_morse_tab()

        # Status bar
        status_bar = ctk.CTkFrame(self.main, fg_color="#f8fafc", corner_radius=12)
        status_bar.grid(row=2, column=0, sticky="ew", padx=22, pady=(0, 18))
        status_bar.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(status_bar, textvariable=self.status_var, text_color="#0f172a").grid(
            row=0, column=0, padx=14, pady=10, sticky="w"
        )

    # ---------- Helpers UI ----------
    def set_status(self, msg: str):
        self.status_var.set(msg)

    def ask_open(self, var: tk.StringVar, patterns: list[tuple[str, str]]):
        p = filedialog.askopenfilename(filetypes=patterns)
        if p:
            var.set(p)
            self.set_status(f"Seleccionado: {os.path.basename(p)}")

    def ask_save(self, var: tk.StringVar, def_ext: str, patterns: list[tuple[str, str]]):
        p = filedialog.asksaveasfilename(defaultextension=def_ext, filetypes=patterns)
        if p:
            var.set(p)
            self.set_status(f"Salida: {os.path.basename(p)}")

    def card(self, parent, title: str):
        frame = ctk.CTkFrame(parent, corner_radius=14, fg_color="#ffffff", border_width=1, border_color="#e5e7eb")
        frame.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(frame, text=title, text_color="#0f172a", font=ctk.CTkFont(size=14, weight="bold")).grid(
            row=0, column=0, padx=14, pady=(12, 8), sticky="w"
        )
        return frame

    # ---------- Tab: Crypto ----------
    def build_crypto_tab(self):
        self.tab_crypto.grid_columnconfigure(0, weight=1)
        self.tab_crypto.grid_rowconfigure(1, weight=1)

        top = ctk.CTkFrame(self.tab_crypto, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=14, pady=14)
        top.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(top, text="Contraseña:", text_color="#0f172a").grid(row=0, column=0, sticky="w")
        self.crypto_pw = ctk.CTkEntry(top, show="•", height=36, placeholder_text="Escribe una contraseña segura…")
        self.crypto_pw.grid(row=0, column=1, sticky="ew", padx=(10, 10))

        self.btn_enc = ctk.CTkButton(top, text="Cifrar", height=36, command=self.do_encrypt)
        self.btn_enc.grid(row=0, column=2, padx=(0, 10))
        self.btn_dec = ctk.CTkButton(top, text="Descifrar", height=36, command=self.do_decrypt, fg_color="#0ea5e9", hover_color="#0284c7")
        self.btn_dec.grid(row=0, column=3)

        body = self.card(self.tab_crypto, "Texto / Cipher Base64")
        body.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        body.grid_rowconfigure(1, weight=1)

        self.crypto_text = ctk.CTkTextbox(body, height=380)
        self.crypto_text.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))

        hint = ctk.CTkLabel(
            body,
            text="Tip: pega aquí el texto plano para cifrar o el Base64 para descifrar.",
            text_color="#64748b",
            font=ctk.CTkFont(size=11)
        )
        hint.grid(row=2, column=0, padx=14, pady=(0, 12), sticky="w")

    def do_encrypt(self):
        try:
            plain = self.crypto_text.get("1.0", "end-1c")
            pw = self.crypto_pw.get()
            res = aes_encrypt(plain, pw)
            self.crypto_text.delete("1.0", "end")
            self.crypto_text.insert("end", res)
            self.set_status("Texto cifrado correctamente.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status("Error al cifrar.")

    def do_decrypt(self):
        try:
            cipher = self.crypto_text.get("1.0", "end-1c")
            pw = self.crypto_pw.get()
            res = aes_decrypt(cipher, pw)
            self.crypto_text.delete("1.0", "end")
            self.crypto_text.insert("end", res)
            self.set_status("Texto descifrado correctamente.")
        except Exception as e:
            messagebox.showerror("Error", f"No se pudo descifrar:\n{e}")
            self.set_status("Error al descifrar.")

    # ---------- Tab: Audio ----------
    def build_audio_tab(self):
        self.tab_audio.grid_columnconfigure(0, weight=1)

        hide = self.card(self.tab_audio, "Ocultar mensaje en WAV (LSB)")
        hide.grid(row=0, column=0, sticky="ew", padx=14, pady=14)
        hide.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(hide, text="WAV cubierta:", text_color="#0f172a").grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")
        ctk.CTkEntry(hide, textvariable=self.audio_cover, height=34).grid(row=1, column=1, padx=10, pady=(0, 10), sticky="ew")
        ctk.CTkButton(hide, text="Elegir", height=34, command=lambda: self.ask_open(self.audio_cover, [("WAV", "*.wav")])).grid(
            row=1, column=2, padx=14, pady=(0, 10)
        )

        ctk.CTkLabel(hide, text="Salida:", text_color="#0f172a").grid(row=2, column=0, padx=14, pady=(0, 10), sticky="w")
        ctk.CTkEntry(hide, textvariable=self.audio_out, height=34).grid(row=2, column=1, padx=10, pady=(0, 10), sticky="ew")
        ctk.CTkButton(hide, text="Guardar como", height=34, command=lambda: self.ask_save(self.audio_out, ".wav", [("WAV", "*.wav")])).grid(
            row=2, column=2, padx=14, pady=(0, 10)
        )

        ctk.CTkLabel(hide, text="Mensaje:", text_color="#0f172a").grid(row=3, column=0, padx=14, pady=(0, 10), sticky="nw")
        self.audio_msg = ctk.CTkTextbox(hide, height=110)
        self.audio_msg.grid(row=3, column=1, padx=10, pady=(0, 10), sticky="ew")

        ctk.CTkButton(hide, text="Ocultar", height=38, command=self.audio_hide).grid(
            row=4, column=2, padx=14, pady=(0, 14), sticky="e"
        )

        ext = self.card(self.tab_audio, "Extraer mensaje desde WAV")
        ext.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 14))
        ext.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ext, text="WAV estego:", text_color="#0f172a").grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")
        ctk.CTkEntry(ext, textvariable=self.audio_stego, height=34).grid(row=1, column=1, padx=10, pady=(0, 10), sticky="ew")
        ctk.CTkButton(ext, text="Elegir", height=34, command=lambda: self.ask_open(self.audio_stego, [("WAV", "*.wav")])).grid(
            row=1, column=2, padx=14, pady=(0, 10)
        )

        self.audio_out_msg = ctk.CTkTextbox(ext, height=110)
        self.audio_out_msg.grid(row=2, column=0, columnspan=2, padx=14, pady=(0, 14), sticky="ew")
        ctk.CTkButton(ext, text="Extraer", height=38, fg_color="#0ea5e9", hover_color="#0284c7", command=self.audio_extract).grid(
            row=2, column=2, padx=14, pady=(0, 14), sticky="e"
        )

    def audio_hide(self):
        try:
            cover = self.audio_cover.get().strip()
            outp = self.audio_out.get().strip()
            msg = self.audio_msg.get("1.0", "end-1c")
            if not cover or not os.path.exists(cover):
                raise ValueError("Selecciona un WAV de cubierta válido.")
            if not outp:
                raise ValueError("Define una ruta de salida.")
            if not msg:
                raise ValueError("El mensaje está vacío.")
            wav_hide(cover, msg, outp)
            messagebox.showinfo("OK", "Mensaje oculto en audio.")
            self.set_status("Audio: ocultación completada.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status("Audio: error al ocultar.")

    def audio_extract(self):
        try:
            stego = self.audio_stego.get().strip()
            if not stego or not os.path.exists(stego):
                raise ValueError("Selecciona un WAV estego válido.")
            msg = wav_extract(stego)
            self.audio_out_msg.delete("1.0", "end")
            self.audio_out_msg.insert("end", msg)
            self.set_status("Audio: extracción completada.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status("Audio: error al extraer.")

    # ---------- Tab: Video ----------
    def build_video_tab(self):
        self.tab_video.grid_columnconfigure(0, weight=1)

        hide = self.card(self.tab_video, "Ocultar mensaje en video (canal B)")
        hide.grid(row=0, column=0, sticky="ew", padx=14, pady=14)
        hide.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(hide, text="Video cubierta:", text_color="#0f172a").grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")
        ctk.CTkEntry(hide, textvariable=self.vid_cover, height=34).grid(row=1, column=1, padx=10, pady=(0, 10), sticky="ew")
        ctk.CTkButton(hide, text="Elegir", height=34, command=lambda: self.ask_open(self.vid_cover, [("Video", "*.mp4 *.avi")])).grid(
            row=1, column=2, padx=14, pady=(0, 10)
        )

        ctk.CTkLabel(hide, text="Salida (mp4):", text_color="#0f172a").grid(row=2, column=0, padx=14, pady=(0, 10), sticky="w")
        ctk.CTkEntry(hide, textvariable=self.vid_out, height=34).grid(row=2, column=1, padx=10, pady=(0, 10), sticky="ew")
        ctk.CTkButton(hide, text="Guardar como", height=34, command=lambda: self.ask_save(self.vid_out, ".mp4", [("MP4", "*.mp4")])).grid(
            row=2, column=2, padx=14, pady=(0, 10)
        )

        ctk.CTkLabel(hide, text="Mensaje:", text_color="#0f172a").grid(row=3, column=0, padx=14, pady=(0, 10), sticky="nw")
        self.vid_msg = ctk.CTkTextbox(hide, height=110)
        self.vid_msg.grid(row=3, column=1, padx=10, pady=(0, 10), sticky="ew")

        ctk.CTkButton(hide, text="Ocultar", height=38, command=self.video_hide).grid(
            row=4, column=2, padx=14, pady=(0, 14), sticky="e"
        )

        ext = self.card(self.tab_video, "Extraer mensaje desde video")
        ext.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 14))
        ext.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(ext, text="Video estego:", text_color="#0f172a").grid(row=1, column=0, padx=14, pady=(0, 10), sticky="w")
        ctk.CTkEntry(ext, textvariable=self.vid_stego, height=34).grid(row=1, column=1, padx=10, pady=(0, 10), sticky="ew")
        ctk.CTkButton(ext, text="Elegir", height=34, command=lambda: self.ask_open(self.vid_stego, [("Video", "*.mp4 *.avi")])).grid(
            row=1, column=2, padx=14, pady=(0, 10)
        )

        self.vid_out_msg = ctk.CTkTextbox(ext, height=110)
        self.vid_out_msg.grid(row=2, column=0, columnspan=2, padx=14, pady=(0, 14), sticky="ew")
        ctk.CTkButton(ext, text="Extraer", height=38, fg_color="#0ea5e9", hover_color="#0284c7", command=self.video_extract).grid(
            row=2, column=2, padx=14, pady=(0, 14), sticky="e"
        )

    def video_hide(self):
        try:
            cover = self.vid_cover.get().strip()
            outp = self.vid_out.get().strip()
            msg = self.vid_msg.get("1.0", "end-1c")

            if not cover or not os.path.exists(cover):
                raise ValueError("Selecciona un video de cubierta válido.")
            if not outp:
                raise ValueError("Define una ruta de salida.")
            if not msg:
                raise ValueError("El mensaje está vacío.")

            self.set_status("Procesando video… esto puede tardar.")
            self.update_idletasks()

            video_hide(cover, msg, outp)

            messagebox.showinfo("OK", "Mensaje oculto en video.")
            self.set_status("Video: ocultación completada.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status("Video: error al ocultar.")

    def video_extract(self):
        try:
            stego = self.vid_stego.get().strip()
            if not stego or not os.path.exists(stego):
                raise ValueError("Selecciona un video estego válido.")

            self.set_status("Extrayendo de video…")
            self.update_idletasks()

            msg = video_extract(stego)
            self.vid_out_msg.delete("1.0", "end")
            self.vid_out_msg.insert("end", msg)
            self.set_status("Video: extracción completada.")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            self.set_status("Video: error al extraer.")

    # ---------- Tab: Morse ----------
    def build_morse_tab(self):
        self.tab_morse.grid_columnconfigure(0, weight=1)

        a = self.card(self.tab_morse, "Texto → Morse")
        a.grid(row=0, column=0, sticky="ew", padx=14, pady=14)
        a.grid_columnconfigure(0, weight=1)

        self.morse_in = ctk.CTkTextbox(a, height=120)
        self.morse_in.grid(row=1, column=0, padx=14, pady=(0, 10), sticky="ew")
        ctk.CTkButton(a, text="Convertir a Morse", height=38, command=self.do_to_morse).grid(
            row=2, column=0, padx=14, pady=(0, 14), sticky="e"
        )

        b = self.card(self.tab_morse, "Morse → Texto")
        b.grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 14))
        b.grid_columnconfigure(0, weight=1)

        self.morse_code = ctk.CTkTextbox(b, height=120)
        self.morse_code.grid(row=1, column=0, padx=14, pady=(0, 10), sticky="ew")
        ctk.CTkButton(b, text="Convertir a Texto", height=38, fg_color="#0ea5e9", hover_color="#0284c7", command=self.do_from_morse).grid(
            row=2, column=0, padx=14, pady=(0, 14), sticky="e"
        )

    def do_to_morse(self):
        code = to_morse(self.morse_in.get("1.0", "end-1c"))
        self.morse_code.delete("1.0", "end")
        self.morse_code.insert("end", code)
        self.set_status("Morse generado.")

    def do_from_morse(self):
        text = from_morse(self.morse_code.get("1.0", "end-1c"))
        self.morse_in.delete("1.0", "end")
        self.morse_in.insert("end", text)
        self.set_status("Texto recuperado desde Morse.")

    # ---------- General ----------
    def clear_all(self):
        # Crypto
        self.crypto_pw.delete(0, "end")
        self.crypto_text.delete("1.0", "end")

        # Audio
        self.audio_cover.set("")
        self.audio_out.set("")
        self.audio_stego.set("")
        self.audio_msg.delete("1.0", "end")
        self.audio_out_msg.delete("1.0", "end")

        # Video
        self.vid_cover.set("")
        self.vid_out.set("")
        self.vid_stego.set("")
        self.vid_msg.delete("1.0", "end")
        self.vid_out_msg.delete("1.0", "end")

        # Morse
        self.morse_in.delete("1.0", "end")
        self.morse_code.delete("1.0", "end")

        self.set_status("Campos limpiados.")

    def show_help(self):
        messagebox.showinfo(
            "Ayuda",
            "CryptoSteg Toolkit\n\n"
            "• Cifrar/Descifrar: AES-CBC (Base64).\n"
            "• Audio Steg: oculta en LSB de WAV.\n"
            "• Video Steg: oculta en LSB del canal B.\n"
            "• Morse: conversiones rápidas.\n\n"
            "Uso recomendado: educación, laboratorios y fines legítimos."
        )


if __name__ == "__main__":
    app = AppCTK()
    app.mainloop()
