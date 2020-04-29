#!/usr/bin/env python
# -*- coding: utf-8 -*-
# ESP: Colorea algunas partes del codigo para una mejor identificacion visual.
# ENG: Color some parts of the code for better visual identification.
#
# @author Gabi Marti. Twitter: @H0l3Bl4ck
# @category Bl4ckH0l3.Colors
# @date 29/04/2020
# @version 0.1
#
# Nota: Esta es una version muy temprana que requiere de bastantes optimizaciones en el codigo.

import time
import ghidra.program.model.listing

from ghidra.program.flatapi import FlatProgramAPI
from ghidra.app.plugin.core.colorizer import ColorizingService
from ghidra.app.script import GhidraScript
from ghidra.program.model.address import Address
from ghidra.program.model.address import AddressSet

from java.awt import Color

# Debug options
DEBUG_ENABLED = True

# Definicion de array de mnemonicos analizados y sus propiedades
#               Mnemonico,  Activo, ShowLog,  Color,                 Contador
aMnemonics = [ ["CALL",     True,   False,    Color(250, 250, 100),  0], 
               ["TEST",     True,   False,    Color(200, 200, 255),  0],
               ["CMP",      True,   True,     Color(255, 50, 50),    0],
               ["JMP",      True,   False,    Color(250, 100, 100),  0],
               ["JZ",       True,   False,    Color(178, 255, 102),  0],
               ["JNZ",      True,   False,    Color(102, 255, 255),  0]
            ]

# Control de tiempo
tiempo_inicio = tiempo_pasado = time.time()

# Servicio de colorizacion
serviceColor = None

# Establece color en funcion del mnemonico si esta activada la opcion
def setColor( direccion, mnemonico ):
    addresses = AddressSet()
    addresses.add(direccion)
    vcolor = Color.WHITE
    muestralog = False

    # busca mnemonico en el array
    for nem in aMnemonics: 
        if mnemonico == nem[0] and nem[1] == True:
            muestra = nem[2]
            vcolor = nem[3]
            nem[4] += 1
            
    if muestralog:
        msg = str(direccion) + " : " + mnemonico + " " +  str(getSymbolAt(direccion)) 
        print(msg)

    # monitor.setMessage(msg)	
    setBackgroundColor(direccion, vcolor)


# Funcion principal de coloreado
def coloreaCodigo():
    primeraDireccion = True

    cProgram = getCurrentProgram()
    minAddress = cProgram.getMinAddress()
    maxAddress = cProgram.getMaxAddress()
    totAddress = int(str(maxAddress),16) - int(str(minAddress),16)
    monitor.initialize(totAddress)
    monitor.setMessage("Coloreando mnemonicos ...")	
    print("Rango de direcciones del programa: {} - {} (total {} bytes)".format(str(minAddress),str(maxAddress),str(totAddress)))

    pList  = cProgram.getListing()
    instructionIterator  = pList.getInstructions(True)
    dirAnterior = int(str(minAddress),16)
    while instructionIterator.hasNext() and not monitor.isCancelled():      
        instruccion = instructionIterator.next()
        # direccion = instruccion.getFallFrom()
        direccion = instruccion.getAddress()
        monitor.setMessage("Coloreando mnemonicos {} ...".format(str(direccion)))	

        # resetea color
        clearBackgroundColor(direccion)

        if primeraDireccion:
            print("Primera direccion : {}".format(direccion))
            primeraDireccion = False
            time.sleep(1)

        mnemonico = instruccion.getMnemonicString()
        salto = int(str(direccion),16) - dirAnterior
        monitor.incrementProgress(salto)  

        if not mnemonico == "None":
            # print(str(direccion) + " : " + mnemonico + " " +  str(getSymbolAt(direccion)))
            setColor(direccion, mnemonico)
            #time.sleep(.01)

        dirAnterior = int(str(direccion),16)
        # comprueba si el usuario cancela el proceso
        monitor.checkCanceled()


    print("Ultima direccion : {}".format(direccion))
    time.sleep(3)
    monitor.setMessage("Proceso finalizado")
    time.sleep(1)


# Muestra estadisticas de menmonicos procesados
def muestraEstadisticas():
    tiempo_pasado = time.time() - tiempo_inicio
    print("Total tiempo procesado {} ".format(time.strftime("%H:%M:%S", time.gmtime(tiempo_pasado))))
    print("Total mnemonicos procesados:")
    for nem in aMnemonics: 
        print(" * {}   \t   {:7d}".format(nem[0],nem[4]))


if __name__ == '__main__':
    if isRunningHeadless():
        print "Este script tiene que funcionar con el GUI de Ghidra"
        exit()

    serviceColor = state.getTool().getService(ColorizingService)
    if serviceColor is None:
        print "No encuentro el servicio 'ColorizingService'"
        exit()

    coloreaCodigo() 
    muestraEstadisticas()

