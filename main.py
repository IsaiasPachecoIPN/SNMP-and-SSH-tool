import functools
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication, QMainWindow, QPushButton, QWidget, QLineEdit
from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel, QTextEdit, QScrollArea
from PySide6.QtGui import QIcon
# Hilo para el servidor SNMP
from PySide6.QtCore import QThread, Signal, QObject

# python snmp trap receiver
from pysnmp.entity import engine, config
from pysnmp.carrier.asyncore.dgram import udp
from pysnmp.entity.rfc3413 import ntfrcv
from pysnmp.smi import builder, view, compiler, rfc1902
from pysnmp.hlapi import *
from quicksnmp import *

# Servidor SSH
import paramiko
import time
conexion = paramiko.SSHClient()
conexion.set_missing_host_key_policy(paramiko.AutoAddPolicy())
isSSHConnected = True


class BandWidthObj():
    def __init__(self):
        self.band_width = 0
        self.time = 0
        self.w1_input = 0
        self.w1_output = 0

    def setValues(self, band_width, time, w1_input, w1_output):
        self.band_width = band_width
        self.time = time
        self.w1_input = w1_input
        self.w1_output = w1_output
        self.name = "no_name"

    def setName(self, name):
        self.name = name

    def getTime(self):
        return self.time

    def getBandWidth(self):
        return self.band_width

    def getW1Input(self):
        return self.w1_input

    def getW1Output(self):
        return self.w1_output

    def getName(self):
        return self.name

    def getValues(self):
        return (self.band_width, self.time, self.w1_input, self.w1_output)

    def str(self):
        return "band: {} time: {} old_walk:{}".format(self.band_width, self.time, self.old_walk)


# Clase para monitorear el uso de banda
class BandwidthMonitor(QThread):

    def __init__(self):
        super().__init__()
        print("entro...")
        self.bandWidth = []
        self.firstTime = True

    def setBandWidth(self, bandWidth):
        self.bandWidth = bandWidth

    def run(self):
        while True:
            try:
                idx_aux = 0
                band_width = []
                reshape_arr_flag = True
                global_time = 0
                for (errorIndication, errorStatus, errorIndex, varBinds) in \
                    nextCmd(
                    SnmpEngine(),
                    CommunityData('cisco'),
                    UdpTransportTarget(('10.0.0.1', 161)),
                    ContextData(),
                    ObjectType(ObjectIdentity('SNMPv2-MIB', 'sysUpTime')),
                    ObjectType(ObjectIdentity('IF-MIB', 'ifInOctets')),
                    ObjectType(ObjectIdentity('IF-MIB', 'ifOutOctets')),
                    ObjectType(ObjectIdentity('IF-MIB', 'ifSpeed')),
                    ObjectType(ObjectIdentity('IF-MIB', 'lifEntry')),
                    lexicographicMode=False
                ):

                    if self.firstTime == True:
                        for i in range(len(varBinds)+1):
                            self.bandWidth.append(BandWidthObj())
                        self.firstTime = False

                    if reshape_arr_flag:
                        for i in range(len(varBinds)+1):
                            band_width.append(BandWidthObj())

                    if errorIndication:
                        print(errorIndication)
                    elif errorStatus:
                        print(errorStatus)
                    else:
                        sysUpTime, ifInOctects, ifOutOctects, ifSpeed, otro = varBinds[
                            0], varBinds[1], varBinds[2], varBinds[3], varBinds[4]

                        if reshape_arr_flag:
                            global_time = float(sysUpTime[1])
                            reshape_arr_flag = False

                        _, old_time, w1_input, w1_output = self.bandWidth[idx_aux].getValues(
                        )

                        input_utilization = float(ifInOctects[1])
                        output_utilization = float(ifOutOctects[1])
                        counter_rollover = 4294967296

                        delta_time = abs(global_time-old_time)

                        _aux = ((w1_input-input_utilization) +
                                (w1_output-output_utilization))*8*100
                        _div = delta_time * float(ifSpeed[1])
                        _res = (_aux/_div)

                        print("delta_t:{}".format(
                            delta_time))

                        print("in_new:{} in_old:{}".format(
                            input_utilization, w1_input))
                        print("out_new:{} out_old:{} res:{}".format(
                            output_utilization, w1_output, _res*100))

                        band_width[idx_aux].setValues(
                            _res, global_time, input_utilization, output_utilization)

                    idx_aux = idx_aux + 1
                self.setBandWidth(bandWidth=band_width)
                print("\n")
                band_width = []
                reshape_arr_flag = True

                #print("after bandWidth: {}".format(self.bandWidth))
            except Exception as e:
                print(e)
                time.sleep(10)
                continue
            time.sleep(10)

# Clase para guardar las señales


class Comunicacion(QObject):
    # Señal para el hilo
    addDialogUpdate = Signal(str, str, str)


# Clase para ejecutar los comandos


class ExecuteCommand(QThread):
    commandUpdate = Signal(str)

    def __init__(self, commando, router_widget):
        super().__init__()

        self.commando = commando
        self.router_widget = router_widget

    def run(self):
        print("Ejecutando comando: " + self.commando)
        conexion.connect(self.router_widget.getIp(), username=self.router_widget.getName(
        ), password=self.router_widget.getPassword(), look_for_keys=False, allow_agent=False)
        nueva_conexion = conexion.invoke_shell()
        nueva_conexion.send(self.commando + "\n")
        time.sleep(3)
        salida = str(nueva_conexion.recv(5000).decode('utf-8'))
        self.commandUpdate.emit(salida)
        time.sleep(3)
        nueva_conexion.close()


# Servidor SNMP


class ServidorSNMP(QThread):

    textUpdate = Signal(str)

    def __init__(self):
        super().__init__()

    def doGet(self, mib):
        print("GET: ", mib)
        try:
            # Se obtienen los objectTypes de las mibs
            mib_objs = []
            mib_items = list(mib.items())
            mib_name = mib_items[0][0]
            mib_value = mib_items[0][1]
            value = ""

            for val in mib_value:
                mib_objs.append(ObjectType(ObjectIdentity(mib_name, val)))

            for (errorIndication, errorStatus, errorIndex, varBinds) in \
                nextCmd(
                SnmpEngine(),
                CommunityData('cisco'),
                UdpTransportTarget(('10.0.0.1', 161)),
                ContextData(),
                *mib_objs,
                lexicographicMode=False
            ):
                if errorIndication:
                    print(errorIndication)
                elif errorStatus:
                    print(errorStatus)
                else:
                    for varBind in varBinds:
                        value = value + \
                            ' = '.join([x.prettyPrint()
                                       for x in varBind]) + '\n'
            self.textUpdate.emit(value)
        except Exception as e:
            self.textUpdate("Error al obtener mib")
            print("Error", e)

    def run(self):
        print("Servidor SNMP iniciado...")
        self.snmpEngine = engine.SnmpEngine()

        self.TrapAgentAddress = '172.16.0.100'  # Trap listerner address
        Port = 162  # trap listerner port

        print("Agent is listening SNMP Trap on " +
              self.TrapAgentAddress+" , Port : " + str(Port))
        print('--------------------------------------------------------------------------')
        config.addTransport(
            self.snmpEngine,
            udp.domainName + (1,),
            udp.UdpTransport().openServerMode((self.TrapAgentAddress, Port))
        )

        # Assemble MIB viewer
        mibBuilder = builder.MibBuilder()
        compiler.addMibCompiler(mibBuilder, sources=['file:///usr/share/snmp/mibs',
                                                     'http://mibs.snmplabs.com/asn1/@mib@'])
        mibViewController = view.MibViewController(mibBuilder)

        # Pre-load MIB modules we expect to work with
        mibBuilder.loadModules('SNMPv2-MIB', 'SNMP-COMMUNITY-MIB')

        # Configure community here
        config.addV1System(self.snmpEngine, 'my-area', 'cisco')

        def cbFun(snmpEngine, stateReference, contextEngineId, contextName,
                  varBinds, cbCtx):
            print("Received new Trap message")
            varBinds = [rfc1902.ObjectType(rfc1902.ObjectIdentity(
                x[0]), x[1]).resolveWithMib(mibViewController) for x in varBinds]
            for name, val in varBinds:
                print('%s = %s' % (name.prettyPrint(), val.prettyPrint()))
                value = str('%s = %s' %
                            (name.prettyPrint(), val.prettyPrint()))
                self.textUpdate.emit(value)

        ntfrcv.NotificationReceiver(self.snmpEngine, cbFun)

        self.snmpEngine.transportDispatcher.jobStarted(1)

        try:
            self.snmpEngine.transportDispatcher.runDispatcher()
        except:
            self.snmpEngine.transportDispatcher.closeDispatcher()
            raise

# Widget para agregar un nuevo router


class AddRouterDialog(QWidget):

    def __init__(self, comunicacion, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Agregar Router")
        self.setFixedSize(300, 200)
        self.setWindowIcon(QIcon("./icons/icon.jpg"))

        # Communication
        self.comunicacion = comunicacion

        # Layout
        layout = QVBoxLayout()  # Layout principal
        layout_btns = QHBoxLayout()  # Layout para los botones

        # Labels
        lbl_nombre = QLabel("Nombre del router:")
        lbl_ip = QLabel("IP del router:")
        lbl_password = QLabel("Password del router:")

        # TextEdits
        self.txt_nombre = QLineEdit()
        self.txt_ip = QLineEdit()
        self.txt_password = QLineEdit()

        # Botones
        btn_agregar = QPushButton("Agregar")
        btn_cancelar = QPushButton("Cancelar")

        # Agregar los elementos al layout
        layout.addWidget(lbl_nombre)
        layout.addWidget(self.txt_nombre)
        layout.addWidget(lbl_ip)
        layout.addWidget(self.txt_ip)
        layout.addWidget(lbl_password)
        layout.addWidget(self.txt_password)

        layout_btns.addWidget(btn_cancelar)
        layout_btns.addWidget(btn_agregar)

        layout.addLayout(layout_btns)

        # Agregar el layout al widget
        self.setLayout(layout)

        # Agregar los eventos a la ventana
        btn_cancelar.clicked.connect(self.close_event)
        btn_agregar.clicked.connect(self.router_ssh_conexion)

    def close_event(self):
        self.close()

    def router_ssh_conexion(self):
        try:
            name = self.txt_nombre.text()
            dir_ip = self.txt_ip.text()
            passw = self.txt_password.text()
            conexion.connect(dir_ip, username=name,
                             password=passw, look_for_keys=False, allow_agent=False)
            self.alert = MessageWidget("Atención", "Conexión exitosa")
            self.comunicacion.addDialogUpdate.emit(name, dir_ip, passw)
            self.alert.show()
            self.close()
        except Exception as e:
            self.alert = MessageWidget("Atención", "Conexión fallida")
            print(e)
            self.alert.show()
            self.close()

# Widget para mostrar mensajes


class MessageWidget(QWidget):
    def __init__(self, msj_title, msj):
        super().__init__()
        self.setWindowTitle(msj_title)
        self.setFixedSize(300, 200)
        self.setWindowIcon(QIcon("./icons/icon.jpg"))

        # Layout
        layout = QVBoxLayout()  # Layout principal
        layout_btns = QHBoxLayout()  # Layout para los botones

        # Labels
        lbl_title = QLabel(
            '<center><strong><p style="font-size:20px;margin: 20px">'+msj_title+'</p></strong></center>')
        lbl_title.setObjectName("titleMessage")
        lbl_mensaje = QLabel(
            '<center><p style="padding: 20px">'+msj+'</p></center>')

        # Botones
        btn_cerrar = QPushButton("Aceptar")

        # Agregar los elementos al layout
        layout.addWidget(lbl_title)
        layout.addWidget(lbl_mensaje)
        layout.setAlignment(Qt.AlignCenter)

        layout_btns.addWidget(btn_cerrar)

        layout.addLayout(layout_btns)

        # Agregar el layout al widget
        self.setLayout(layout)

        # Agregar los eventos a la ventana
        btn_cerrar.clicked.connect(self.close_event)

    def close_event(self):
        self.close()

# Widget para la vista de los routers


class RouterWidget(QWidget):
    def __init__(self, comunicacion, name, ip, password=None):
        super().__init__()

        self.comunicacion = comunicacion
        self.name = name
        self.ip = ip
        self.password = password

        # Layout vertical
        layout = QVBoxLayout()

        # Labels
        self.lbl_router_name = QLabel(
            "<strong>Nombre del router:<atrong> <font color=#4153ba> {} </font>".format(self.name))
        self.lbl_router_ip = QLabel(
            "<strong>Router IP:<atrong> <font color=#4153ba> {} </font>".format(self.ip))

        # Se agrega los elementos al layout
        layout.addWidget(self.lbl_router_name)
        layout.addWidget(self.lbl_router_ip)

        # Se agrega la señal
        self.comunicacion.addDialogUpdate.connect(self.onRouterAdded)

        self.setLayout(layout)

    def getIp(self):
        return self.ip

    def getPassword(self):
        return self.password

    def getName(self):
        return self.name

    def onRouterAdded(self, name, ip, password):
        print("Router agregado")
        self.name = name
        self.ip = ip
        self.password = password

        self.lbl_router_name.setText(
            "<strong>Nombre del router:<atrong> <font color=#4153ba> {} </font>".format(self.name))
        self.lbl_router_ip.setText(
            "<strong>Router IP:<atrong> <font color=#4153ba> {} </font>".format(self.ip))

    def setRouterValues(self, name, ip, password):
        self.name = name
        self.ip = ip
        self.password = password


class MainScreen(QWidget):
    def __init__(self, comunicacion):
        super().__init__()

        # Comunicacion
        self.comunicacion = comunicacion

        # My widgets
        self.router_widget = RouterWidget(
            self.comunicacion, "Router", "No conectado", "12345")

        # Layouts
        layout = QVBoxLayout()  # Layout principal
        layout_router_info = QHBoxLayout()  # Layout para la información del router
        layout_cmd = QHBoxLayout()  # Layout para ingresar los comandos
        # Layout para mostrar el output del terminal
        layout_terminal_output = QHBoxLayout()
        # Layout para mostrar los errores y notificaciones
        layout_errors_notifications = QVBoxLayout()

        # Labels
        # Label para ingresar los comandos
        lbl_cmd_opt = QLabel("Ingresar comandos:")
        # Label para mostrar el output del terminal
        lbl_terminal_output = QLabel("Salida:")
        lbl_snmp_output = QLabel("SNMP - Traps")

        # TextEdit
        self.command_input = QTextEdit()  # TextEdit para ingresar los comandos
        self.terminal_output = QTextEdit()  # TextEdit para mostrar el output del terminal
        self.snmp_output = QTextEdit()  # TextEdit para el servidor SNMP

        # Servidor SNMP
        self.snmp_server = ServidorSNMP()
        self.snmp_server.start()

        # Monitor de banda
        # self.bandwidth_monitor = BandwidthMonitor()
        # self.bandwidth_monitor.start()

        self.snmp_server.textUpdate.connect(self.onRecieveTrap)

        # TextEdit styles
        self.command_input.setFixedHeight(50)  # Ancho del TextEdit
        self.command_input.setObjectName("commandInput")
        self.terminal_output.setFixedWidth(700)
        self.terminal_output.setObjectName("commandOutput")
        self.terminal_output.setReadOnly(True)
        self.snmp_output.setReadOnly(True)
        self.snmp_output.setObjectName("commandInput")

        # Boton para los comandos
        btn_cmd = QPushButton("Ejecutar")
        btn_cmd.setObjectName("runButton")

        # btn_cerrar.clicked.connect(self.close_event)
        btn_cmd.clicked.connect(self.executeCommand)

        # Agregar los elementos al layout
        # Agregar el TextEdit para ingresar los comandos
        layout_cmd.addWidget(self.command_input)
        # Agregar el boton para ejecutar los comandos
        layout_cmd.addWidget(btn_cmd)

        # Agregar los elementos del layuout para la salida del terminal
        layout_terminal_output.addWidget(self.terminal_output)

        # Agregar los elementos al layout router
        layout_router_info.addWidget(self.router_widget)

        # Agregar los elementos al layout principal
        layout.addLayout(layout_router_info)
        layout.addWidget(lbl_cmd_opt)
        layout.addLayout(layout_cmd)
        layout.addWidget(lbl_terminal_output)
        layout.addLayout(layout_terminal_output)
        layout.addWidget(lbl_snmp_output)
        layout.addWidget(self.snmp_output)

        # Setear el layout principal
        self.setLayout(layout)

    def onRecieveTrap(self, trap):
        print("Recibiendo trap")
        self.snmp_output.append(trap)

    def onRecieveCommandOutput(self, output):
        print("Salida del comando")
        self.terminal_output.append(output)

    def executeCommand(self):
        if (self.router_widget.getPassword() != None):
            # Se obtiene el comando de la caja de texto
            commando = self.command_input.toPlainText()
            # Se ejecuta el comando en un nuevo hilo
            self.commands = ExecuteCommand(commando, self.router_widget)
            self.commands.start()
            self.commands.commandUpdate.connect(self.onRecieveCommandOutput)
        else:
            self.dialog = MessageWidget(
                "Atención", "No se ha encontrado ninguna conexión válida")
            self.dialog.show()
# Ventana principal


class MainWindow(QMainWindow):
    def __init__(self, comunicacion):
        super(MainWindow, self).__init__()

        # Clase para guardar las MIBS
        # Objeto con las operaciones mibs para la operación GET
        myMibs = {
            'SYS_NAME': {'SNMPv2-MIB': ['sysName']},
            'SYS_DESC': {'SNMPv2-MIB': ['sysDescr']},
            'SYS_UP_TIME': {'SNMPv2-MIB': ['sysUpTime']},
            'SYS_CONTACT': {'SNMPv2-MIB': ['sysContact']},
            'IF_TABLE': {'IF-MIB': ['ifDescr', 'ifType', 'ifMtu', 'ifSpeed', 'ifPhysAddress']},
            'IP_ADDR_TABLE': {'IP-MIB': ['ipAdEntAddr', 'ipAdEntNetMask']},
            'IP_ROUTE_TABLE': {'RFC1213-MIB': ['ipRouteDest', 'ipRouteNextHop', 'ipRouteType', 'ipRouteProto', 'ipRouteMask']}
        }
        # Comunicacion
        self.comunicacion = comunicacion

        # Title
        self.setWindowTitle("IPC - SSH Tool")

        # Menu
        self.menu = self.menuBar()
        self.router = self.menu.addMenu("Router")
        self.snmp = self.menu.addMenu("SNMP-GET")

        # Screens
        self.mainScreen = MainScreen(comunicacion)
        self.setCentralWidget(self.mainScreen)

        # Actions
        self.router.addAction("Agregar")

        for key in myMibs.keys():
            self.snmp.addAction(str(key), functools.partial(
                self.mainScreen.snmp_server.doGet, myMibs[key]))

        # self.snmp.addAction("get")
        # self.snmp.triggered.connect(self.mainScreen.snmp_server.doGet)

        # Señal para la accion
        self.router.triggered.connect(self.open_add_router_dialog)

    def open_add_router_dialog(self):
        self.router_dialog = AddRouterDialog(comunicacion)
        self.router_dialog.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    comunicacion = Comunicacion()
    window = MainWindow(comunicacion)
    window.setWindowIcon(QIcon("./icons/icon.jpg"))
    window.resize(800, 600)
    window.show()

    with open("./icons/styles.qss", "r") as f:
        _style = f.read()
        app.setStyleSheet(_style)

    sys.exit(app.exec())
