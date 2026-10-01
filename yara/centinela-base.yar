/*
  Centinela — reglas YARA base (genéricas y defensivas)
  Detectan características estructurales de archivos de riesgo, no familias concretas de malware.
  Compatibles con el subconjunto de YARA del sandbox de Centinela y con YARA estándar.
  Licencia: la misma del proyecto. Ajusta "severity" a tu política.
*/

rule Centinela_PE_empaquetado_UPX : empaquetador
{
  meta:
    description = "Ejecutable de Windows empaquetado con UPX"
    severity = "medium"
    attack = "T1027.002"
  strings:
    $s0 = "UPX0"
    $s1 = "UPX1"
  condition:
    uint16(0) == 0x5A4D and all of them
}

rule Centinela_Office_macro_autoejecutable : documento
{
  meta:
    description = "Documento de Office con proyecto VBA y macro de ejecución automática"
    severity = "high"
    attack = "T1204.002 T1059.005"
  strings:
    $vba = "_VBA_PROJECT" wide ascii
    $a1 = "AutoOpen" nocase
    $a2 = "Document_Open" nocase
    $a3 = "Workbook_Open" nocase
  condition:
    $vba and any of ($a*)
}

rule Centinela_PDF_javascript_al_abrir : documento
{
  meta:
    description = "PDF con JavaScript y acción automática al abrirse"
    severity = "medium"
    attack = "T1204.002 T1059.007"
  strings:
    $js1 = "/JavaScript"
    $js2 = "/JS"
    $open = "/OpenAction"
    $aa = "/AA"
  condition:
    uint32(0) == 0x46445025 and any of ($js*) and ($open or $aa)
}

rule Centinela_LNK_ejecuta_interprete : acceso_directo
{
  meta:
    description = "Acceso directo de Windows que invoca un intérprete de comandos"
    severity = "high"
    attack = "T1204.002 T1059"
  strings:
    $p1 = "powershell" nocase wide ascii
    $p2 = "cmd.exe" nocase wide ascii
    $p3 = "mshta" nocase wide ascii
    $p4 = "wscript" nocase wide ascii
  condition:
    uint32(0) == 0x0000004C and any of them
}

rule Centinela_Imagen_disco_con_ejecutable : contenedor
{
  meta:
    description = "Imagen ISO que contiene ejecutables, scripts o accesos directos"
    severity = "medium"
    attack = "T1553.005"
  strings:
    $iso = "CD001"
    $e1 = ".EXE;1" nocase
    $e2 = ".LNK;1" nocase
    $e3 = ".JS;1" nocase
    $e4 = ".VBS;1" nocase
  condition:
    $iso in (0x8000..0x9010) and any of ($e*)
}

rule Centinela_HTML_genera_descarga : html
{
  meta:
    description = "Página HTML que genera un archivo para descargar desde JavaScript (posible HTML smuggling)"
    severity = "medium"
    attack = "T1027.006"
  strings:
    $b1 = "new Blob(" nocase
    $b2 = "createObjectURL" nocase
    $d = ".download" nocase
    $a = "atob(" nocase
  condition:
    filesize < 10MB and $b1 and $b2 and $d and $a
}

rule Centinela_Comprimido_doble_extension : contenedor
{
  meta:
    description = "ZIP que contiene un archivo con doble extensión (documento.pdf.exe)"
    severity = "high"
    attack = "T1036.007"
  strings:
    $d = /\.(pdf|docx?|xlsx?|jpg|png|txt)\.(exe|scr|js|vbs|hta|lnk|bat|cmd)/i
  condition:
    uint32(0) == 0x04034B50 and $d
}
