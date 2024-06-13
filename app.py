import csv
import os
from io import BytesIO
from zipfile import ZipFile

import streamlit as st
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa


def generate_and_save_keys(user):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    user_dir = os.path.join("users", user)
    os.makedirs(user_dir, exist_ok=True)

    # Guardar las claves en archivos específicos del usuario
    with open(os.path.join(user_dir, "private_key.pem"), "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open(os.path.join(user_dir, "public_key.pem"), "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

    return private_key, public_key


def sign_document(document_data, private_key, user, password):
    # Agregar el usuario y la contraseña al contenido del documento
    document_data += (user + password).encode()

    signature = private_key.sign(
        document_data,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256(),
    )
    return signature


def verify_signature(document_data, signature, public_key, user, password):
    # Agregar el usuario y la contraseña al contenido del documento
    document_data += (user + password).encode()

    try:
        public_key.verify(
            signature,
            document_data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )
        return True
    except Exception as e:
        return False


# Guardar usuario y contraseña en un archivo CSV
def save_user_password(user, password):
    if user_exists(user):
        return False

    file_exists = os.path.isfile("usuarios.csv")
    with open("usuarios.csv", mode="a", newline="") as file:
        writer = csv.writer(file)
        if not file_exists:
            writer.writerow(["Usuario", "Contraseña"])  # Escribir encabezado
        writer.writerow([user, password])

    generate_and_save_keys(user)
    return True


# Verificar si el usuario ya existe en el archivo CSV
def user_exists(user):
    if not os.path.exists("usuarios.csv"):
        return False
    with open("usuarios.csv", mode="r") as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == user:
                return True
    return False


# Verificar usuario y contraseña en el archivo CSV
def verify_user_password(user, password):
    if not os.path.exists("usuarios.csv"):
        return False
    with open("usuarios.csv", mode="r") as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == user and row[1] == password:
                return True
    return False


# Función para autenticar firma digital
def authenticate_signature(signature, document_data, user):
    if not user_exists(user):
        return False

    user_dir = os.path.join("users", user)
    with open(os.path.join(user_dir, "public_key.pem"), "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    with open("usuarios.csv", mode="r") as file:
        reader = csv.reader(file)
        for row in reader:
            if row[0] == user:
                password = row[1]
                if verify_signature(
                    document_data, signature, public_key, user, password
                ):
                    return True
    return False


# Función para cerrar sesión
def logout():
    st.session_state["logged_in"] = False
    st.session_state["user"] = None
    st.session_state["password"] = None
    st.session_state["zip_buffer"] = None
    st.session_state["zip_name"] = None
    st.session_state["signature"] = None
    st.session_state["signature_name"] = None


# Interfaz de Streamlit
st.title("Firma Digital")

menu = ["Registrar", "Iniciar Sesión", "Autenticar"]
choice = st.sidebar.selectbox("Menú", menu, on_change=logout)

if choice == "Registrar":
    st.subheader("Registrar Usuario")
    user = st.text_input("Usuario")
    password = st.text_input("Contraseña", type="password")
    if st.button("Registrar"):
        if user and password:
            if save_user_password(user, password):
                st.success("Usuario registrado exitosamente.")
            else:
                st.error(
                    "El nombre de usuario ya existe. Por favor, elija otro nombre de usuario."
                )
        else:
            st.error("Debe introducir un nombre de usuario y una contraseña.")

elif choice == "Iniciar Sesión":
    st.subheader("Iniciar Sesión")
    user = st.text_input("Usuario", key="login_user")
    password = st.text_input("Contraseña", type="password", key="login_pass")
    if st.button("Iniciar Sesión"):
        if verify_user_password(user, password):
            st.session_state["logged_in"] = True
            st.session_state["user"] = user
            st.session_state["password"] = password
            st.success(f"Bienvenido, {user}")
        else:
            st.error("Usuario o contraseña incorrectos.")

if "logged_in" in st.session_state and st.session_state["logged_in"]:
    st.subheader("Firmar Documento")
    document_file = st.file_uploader(
        "Seleccione el documento a firmar", type=["txt", "pdf", "docx"]
    )
    if document_file is not None:
        document_data = document_file.read()
        document_name = document_file.name

        if st.button("Firmar Documento"):
            user_dir = os.path.join("users", st.session_state["user"])
            with open(os.path.join(user_dir, "private_key.pem"), "rb") as f:
                private_key = serialization.load_pem_private_key(
                    f.read(), password=None
                )

            signature = sign_document(
                document_data,
                private_key,
                st.session_state["user"],
                st.session_state["password"],
            )

            signature_name = f"{st.session_state['user']}_{os.path.splitext(document_name)[0]}_signature.sig"
            zip_name = (
                f"{st.session_state['user']}_{os.path.splitext(document_name)[0]}.zip"
            )

            # Crear el archivo zip en memoria
            zip_buffer = BytesIO()
            with ZipFile(zip_buffer, "w") as zip_file:
                zip_file.writestr(document_name, document_data)
                zip_file.writestr(signature_name, signature)

            zip_buffer.seek(0)

            # Almacenar el zip y la firma en el estado de sesión de Streamlit
            st.session_state["zip_buffer"] = zip_buffer
            st.session_state["zip_name"] = zip_name
            st.session_state["signature"] = signature
            st.session_state["signature_name"] = signature_name

            st.success("Documento firmado con éxito.")

    if (
        "zip_buffer" in st.session_state
        and "zip_name" in st.session_state
        and st.session_state["zip_buffer"] is not None
    ):
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                "Descargar ZIP",
                data=st.session_state["zip_buffer"],
                file_name=st.session_state["zip_name"],
            )
        with col2:
            st.download_button(
                "Descargar Firma",
                data=st.session_state["signature"],
                file_name=st.session_state["signature_name"],
            )

elif choice == "Autenticar":
    st.subheader("Autenticar Firma Digital")
    user = st.text_input("Usuario que firmó el documento")
    signature_file = st.file_uploader(
        "Seleccione el archivo de la firma digital", type=["sig"]
    )
    document_file = st.file_uploader(
        "Seleccione el documento firmado", type=["txt", "pdf", "docx"]
    )
    if st.button("Autenticar"):
        if user and signature_file and document_file:
            signature = signature_file.read()
            document_data = document_file.read()

            if authenticate_signature(signature, document_data, user):
                st.success("La autenticación ha sido exitosa.")
            else:
                st.error("La autenticación ha fallado.")
        else:
            st.error(
                "Debe proporcionar el usuario, el archivo de la firma digital y el documento firmado."
            )
