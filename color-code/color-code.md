# Color-Code

## Instalación

Copia el script **Color-Code.py** en el directorio de scripts de Ghidra. Normalmente **$USER_HOME/ghidra_scripts**

Tras reiniciar **Ghidra** al cargar el **"Script Manager"** en la ventana denetro de la sección **Colors** encontrarás este script.

![img_001](img/img-001.png "Script Manager") 

## Uso

Tras ejecutar el script, aparecerá un cuadro de diálogo que pedirá que mnemonicos se quieren colorear.

![img_002](img/img-002.png "dialogo 1") 

Después pedirá que mnemónicos se quieren mostrar en el log de consola.

![img_003](img/img-003.png "dialogo 2") 

Seguidamente se mostrará un cuadro de diálogo con el progreso del proceso.

![img_004](img/img-004.png "ejecución") 

Al finalizar muestra una estadistica del tiempo de procesado y los mnemonicos que ha tratado y coloreado.

En el listado del codigo veremos estos mnemonicos coloreados.

![img_005](img/img-005.png "resultado") 

Ejemplo de resultado con cambios efectuados en **v0.2**

![img_006](img/img-006.png "resultado") 

## Customización del código

El script tiene al principio un array multidimensional que se puede completar a gusto de cada usuario. Añadiendo o quitando mnemonicos y definiendo el color que se desea.

![img_007](img/img-007.png "customización") 

## Descarga

[**Color-Code.py**](Color-Code.py)

## Historial de versiones

**v0.1**    29/04/2020  Lista mnemonicos a procesar fija en array

**v0.2**    01/05/2020  Se permite seleccionar que mnemonicos se colorean y muestran en log mediante cuadro de dialogo.
                        Opcion en barra de menu de Ghidra