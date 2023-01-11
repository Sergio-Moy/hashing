from sha import sha256
from md5 import md5me

import dearpygui.dearpygui as dpg

dpg.create_context()


def ejecutar():
    msg = dpg.get_value(1)
    opt = dpg.get_value(3)
    if opt == 'SHA-256':
        output = sha256(msg)
    else:
        output = md5me(msg)
    dpg.set_value(item=2, value=output)
with dpg.window(tag="Main"):
    dpg.add_text("Mensaje a encriptar ")
    dpg.add_same_line()
    dpg.add_input_text(tag = 1, hint="Escriba su mensaje")
    dpg.add_text("Algoritmo a utilizar")
    dpg.add_radio_button(['SHA-256', 'MD-5'], tag=3, default_value="SHA-256")
    dpg.add_button(label="Encriptar", callback=ejecutar)
    dpg.add_text("Hash ")
    dpg.add_same_line()
    dpg.add_input_text(tag = 2, readonly=True, width=500)


dpg.create_viewport(title='Algoritmos de Cifrado', width=600, height=200)
dpg.setup_dearpygui()
dpg.show_viewport()
dpg.set_primary_window("Main", True)

dpg.start_dearpygui()
dpg.destroy_context()

