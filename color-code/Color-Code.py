# ESP: Colorea algunas partes del codigo para una mejor identificacion visual.
# ENG: Color some parts of the code for better visual identification.
#
#@author Gabi Marti. Twitter: @H0l3Bl4ck
#@category Colors
#@keybinding
#@menupath Tools.Misc.Color Code
#@toolbar 
#
# date 01/05/2020  
# version 0.2
#
# Nota: Esta es una version muy temprana que requiere de algunas optimizaciones en el codigo.
#
# Historial de versiones
#   v0.1    29/04/2020  Lista mnemonicos a procesar fija en array
#   v0.2    01/05/2020  Se permite seleccionar que mnemonicos se colorean y muestran en log mediante cuadro de dialogo.
#                       Opcion en barra de menu de Ghidra


import time
import ghidra.program.model.listing

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet

from java.awt import Color

# Debug options
DEBUG_ENABLED = False

# Posiciones de campos
C_MNEMONICO = 0                         # Nombre del mnemonico
C_SETCOLOR = 1                          # Si se colorea. Se pide en cuadro de dialogo
C_SHOWLOG = 2                           # Si se muestra en la consola de log. Se pide en cuadro de dialogo
C_COLOR = 3                             # Color de background establecido
C_CONTADOR = 4                          # Contador de instrucciones procesadas.


# Definicion de array de mnemonicos analizados y sus propiedades
#               Mnemonico,  SetColor,   ShowLog,  Color,                 Contador
aMnemonics = [ ["CALL",     False,      False,    Color(250, 250, 100),     0], 
               ["TEST",     False,      False,    Color(200, 200, 255),     0],
               ["CMP",      False,      False,    Color(255, 50, 50),       0],
               ["JMP",      False,      False,    Color(240, 190, 190),     0],
               ["JZ",       False,      False,    Color(178, 255, 102),     0],
               ["JNZ",      False,      False,    Color(102, 255, 255),     0],
               ["XOR",      False,      False,    Color(200, 150, 150),     0],
               ["AND",      False,      False,    Color(210, 160, 160),     0],
               ["INT",      False,      False,    Color(210, 200, 160),     0],
               ["LODS",     False,      False,    Color(170, 200, 180),     0]
            ]


# Control de tiempo
tiempo_inicio = tiempo_pasado = time.time()

# Servicio de colorizacion
serviceColor = None


# Pide al usuario que Mnemonicos quiere procesar
def preguntaMnemonicos():
    titulo = "Elige Mnemonicos"

    elementos = []
    descripciones = []
    c = 0
    for nem in aMnemonics:
        elementos.append(c)
        descripciones.append(nem[C_MNEMONICO])
        c += 1

    # Mnemonicos que se van colorear
    texto = "Por favor, elige los mnemonicos que quieres colorear"
    eleccion = askChoices(titulo, texto, elementos, descripciones)

    print("Se coleararn los mnemonicos:")
    for elemento in eleccion: 
        aMnemonics[elemento][C_SETCOLOR] = True
        print(aMnemonics[elemento][C_MNEMONICO])

    time.sleep(1)

    # Mnemonicos que se van a mostrar en el Log de consola
    texto = "Por favor, elige los mnemonicos que quieres mostrar en el Log de Consola"
    eleccion = askChoices(titulo, texto, elementos, descripciones)

    print("Se mostraran en el Log de consola los mnemonicos:")
    for elemento in eleccion: 
        aMnemonics[elemento][C_SHOWLOG] = True
        print(aMnemonics[elemento][C_MNEMONICO])

    time.sleep(1)


# Establece color en funcion del mnemonico si esta activada la opcion
def setColor( direccion, mnemonico ):
    addresses = AddressSet()
    addresses.add(direccion)
    vcolor = Color.WHITE            # Por defecto colorea a blanco para borrar colores anteriores

    # busca mnemonico en el array
    for nem in aMnemonics: 
        if mnemonico == nem[C_MNEMONICO]:
            nem[C_CONTADOR] += 1
        
            if nem[C_SETCOLOR] == True:
                vcolor = nem[C_COLOR]
            
            if nem[C_SHOWLOG]:
                label = str(getSymbolAt(direccion)) 
                if not label == "None":
                    print(label) + ": "
                msg = "  " + str(direccion) + " : " + mnemonico + " "
                print(msg)

    setBackgroundColor(direccion, vcolor)


# Funcion principal de coloreado y log en consola de mnemonicos
def procesaCodigo():
    primeraDireccion = True

    cProgram = getCurrentProgram()
    minAddress = cProgram.getMinAddress()
    maxAddress = cProgram.getMaxAddress()
    totAddress = int(str(maxAddress),16) - int(str(minAddress),16)
    monitor.initialize(totAddress)
    monitor.setMessage("Procesando mnemonicos ...")	
    print("Rango de direcciones del programa: {} - {} (total {} bytes)".format(str(minAddress),str(maxAddress),str(totAddress)))

    pList  = cProgram.getListing()
    instructionIterator  = pList.getInstructions(True)
    dirAnterior = int(str(minAddress),16)
    while instructionIterator.hasNext() and not monitor.isCancelled():      
        instruccion = instructionIterator.next()
        direccion = instruccion.getAddress()
        monitor.setMessage("Coloreando mnemonicos {} ...".format(str(direccion)))	

        # resetea color
        clearBackgroundColor(direccion)

        if primeraDireccion:
            print("Primera direccion : {}".format(direccion))
            primeraDireccion = False
            time.sleep(1)

        mnemonico = instruccion.getMnemonicString()

        # Control barra de progreso
        salto = int(str(direccion),16) - dirAnterior
        monitor.incrementProgress(salto)  

        if not mnemonico == "None":
            setColor(direccion, mnemonico)

        dirAnterior = int(str(direccion),16)

        # comprueba si el usuario cancela el proceso
        monitor.checkCanceled()


    print("Ultima direccion : {}".format(direccion))
    time.sleep(1)
    monitor.setMessage("Proceso finalizado")
    time.sleep(1)


# Muestra estadisticas de menmonicos procesados
def muestraEstadisticas():
    tiempo_pasado = time.time() - tiempo_inicio
    print("Total tiempo procesado {} ".format(time.strftime("%H:%M:%S", time.gmtime(tiempo_pasado))))
    print("Total mnemonicos procesados:")
    for nem in aMnemonics: 
        if nem[C_CONTADOR] > 0:
            print(" * {}   \t   {:7d}".format(nem[C_MNEMONICO],nem[C_CONTADOR]))


if __name__ == '__main__':
    if isRunningHeadless():
        print "Este script tiene que funcionar con el GUI de Ghidra"
        exit()

    serviceColor = state.getTool().getService(ColorizingService)
    if serviceColor is None:
        print "No encuentro el servicio 'ColorizingService'"
        exit()

    preguntaMnemonicos()
    procesaCodigo() 
    muestraEstadisticas()

