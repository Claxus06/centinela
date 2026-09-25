# Política de seguridad

Centinela es una herramienta de ciberseguridad, así que nos tomamos en serio cualquier fallo en la propia aplicación.

## Versión soportada

Solo se mantiene la versión publicada en <https://claxus06.github.io/centinela/> (rama `main`).

## Cómo reportar una vulnerabilidad

**No abras un *issue* público.** Usa el reporte privado de GitHub:

1. Entra a la pestaña **Security** de este repositorio.
2. Pulsa **Report a vulnerability**.
3. Describe el problema, los pasos para reproducirlo y el impacto que ves.

El reporte solo lo ven los mantenedores. Te responderemos por el mismo hilo y te avisaremos cuando esté corregido. Si quieres, te daremos crédito en la corrección.

## Qué entra en el alcance

- Ejecución de código o XSS en la aplicación (`index.html`, `404.html`, `sw.js`).
- Fugas de datos: claves, ajustes o historial que salgan del navegador sin que el usuario lo pida.
- Debilidades en la política de seguridad de contenido (CSP) o en el *service worker*.
- Resultados manipulables que puedan llevar a un usuario a confiar en un sitio malicioso.

## Qué no entra

- Los servicios externos que consulta la app (resolutores DNS, crt.sh, Shodan InternetDB, RDAP, CIRCL, CISA, geo-IP). Repórtalos a cada proveedor.
- Las cabeceras HTTP que GitHub Pages no permite configurar (por ejemplo `X-Frame-Options`). Es una limitación conocida del alojamiento.
- Resultados heurísticos que no coinciden con tu criterio. Son orientativos por diseño; abre un *issue* normal para mejorarlos.

## Uso responsable

Centinela hace evaluaciones **pasivas** con fuentes públicas. Úsala solo sobre dominios e infraestructura propios o para los que tengas autorización.
