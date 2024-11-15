# Proyecto de Auditoría

Este proyecto es una aplicación web desarrollada en Flask para gestionar usuarios y productos con funcionalidades de autenticación y permisos de acceso.

## Requisitos

Asegúrate de tener instalados los siguientes programas en tu sistema:

- Python 3.7 o superior
- Pip (gestor de paquetes de Python)
- Git (para controlar versiones y subir al repositorio)

## Instalación

1. **Clona el repositorio** en tu máquina local:

   ```bash
   git clone https://github.com/JPGA12/CRUD-Registro.git
   cd /CRUD-Registro
2. **Crea y activa un entorno virtual y activalo**(opcional pero recomendado):
   ```bash
   #Creal el entorno virtual
    python3 -m venv env
   #Activa el entorno virtual
    source env/bin/activate  # En macOS y Linux
    env\Scripts\activate  # En Windows
3. **Instala las dependencias listadas en el archivo requirements.txt:**
   ```bash
   pip install -r requirements.txt


## Ejecución del Proyecto
  **Para ejecutar la aplicación, usa el siguiente comando:**

  Carga los detalles graficos con Tailwind
   
      npx tailwindcss -i ./static/css/input.css -o ./static/css/output.css --watch\ 
      
   Ejecuta el servidor con Flas
   
      flask run
  **Esto iniciará el servidor de desarrollo en** http://127.0.0.1:5000.

## Consideraciones de Seguridad

Este proyecto usa Flask en modo de desarrollo y no es adecuado para producción. Asegúrate de configurar un servidor WSGI como Gunicorn para producción y usar un entorno seguro para la base de datos y las variables de entorno.

## Contribución

Si deseas contribuir, por favor realiza un fork del repositorio, crea una nueva rama para tus cambios, y abre un pull request.

## Licencia

Este proyecto está bajo la Licencia MIT. Para más detalles, consulta el archivo LICENSE.


Este `README.md` ofrece una guía completa sobre cómo instalar, configurar y ejecutar el proyecto. Puedes modificar cualquier sección que sea específica para tu caso.
