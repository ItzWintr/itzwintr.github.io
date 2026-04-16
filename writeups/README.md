# 🚀 Cómo Añadir Nuevos Writeups al Portfolio

Esta documentación contiene los pasos para agregar una nueva máquina al sistema dinámico de lectura de apuntes (Estilo Obsidian) sin romper el diseño ni tener que tocar código profundo.

El diseño actual ya tiene configurado:
- **Estilos inmersivos** (Fondo animado, tipografías).
- **Consolas de código** con colores Neón y marcadores (Estilo ventana macOS).
- **Interpretador de Obsidian** (Permite que el formato `![[imagen.png]]` cargue la imagen correctamente en la web).
- **Renderizador matemático (MathJax)** para las fórmulas en LaTeX.

---

## 🛠️ Pasos para Subir una Máquina Nueva

Imaginemos que vamos a añadir el Writeup de una máquina llamada **"PwnBox"**.

### Paso 1: Crear el Directorio Prerrequisito
1. Navega a la carpeta `/writeups/` y crea una carpeta con el nombre de tu máquina. En este caso: `/writeups/PWNBOX`.
2. Mete dentro de esta carpeta todas tus capturas de pantalla importadas desde tu bóveda de Obsidian.

### Paso 2: Copiar la Plantilla Mágica
La magia del diseño vive en el archivo `index.html` que está actualmente en la carpeta de `SILENTIUMHTB`.
1. Entra a `/writeups/SILENTIUMHTB/` y **copia** el archivo `index.html`.
2. **Pégalo** dentro de tu nueva carpeta `/writeups/PWNBOX/`.

### Paso 3: Configurar el nuevo `index.html`
Abre este nuevo `index.html` en tu editor de código (VS Code, etc.) y modifica únicamente 2 cosas:

#### A. El Título de la Pestaña
Busca en las primeras líneas la etiqueta de título (línea 5 aprox.):
```html
<title>Silentium - Hack The Box Machine</title>
```
Cámbialo por `<title>PwnBox - Hack The Box Machine</title>`.

#### B. Pegar tu Apunte (IMPORTANTE)
Desplázate abajo del todo. Justo antes de que acabe el archivo (`</body>`), encontrarás una gran etiqueta `<textarea>` que luce así:
```html
<textarea id="embedded-markdown" style="display:none;">
... TODO EL TEXTO CRUDO DEL WRITEUP ANTERIOR ...
</textarea>
```
1. Borra todo el texto viejo que hay dentro.
2. Ve a Obsidian, selecciona todo tu apunte crudo del nuevo Writeup (`Crtl+A / Crtl+C`).
3. **Pégalo tal cual dentro de la etiqueta `<textarea>`.**

*Nota: No tienes ni que pasar las imágenes a formato web (`<img src=...`). ¡Déjalas con los corchetes `![[Pasted image...]]` y el motor de este archivo se encargará de interpretarlo!*

### Paso 4: Publicarlo en el Portfolio principal
Finalmente, para que un visitante de la web pueda acceder:
1. Abre el documento principal `index.html` de la **raíz de tu proyecto** (tu Portfolio master).
2. Busca la sección dedicada a `<section id="writeups"...>`
3. Copia el bloque entero de la `<div class="card glass-panel cursor-pointer...">` de Silentium o Cybercrafted.
4. Pégalo inmediatamente debajo y ajusta:
   - **El enlace:** Cambia el `href="writeups/SILENTIUMHTB/index.html"` a `href="writeups/PWNBOX/index.html"`
   - **El nombre, dificultad e icono** para que refleje los datos de la nueva máquina.

---

### 🎉 ¡Listo!
Si haces `. git push` o abres tu Live Server, verás que la nueva tarjeta redirige al nuevo Writeup con el mismo aspecto impecable y la caja de comandos flotante sin que hayas sudado una gota de CSS.

**Happy Hacking!** 💻
